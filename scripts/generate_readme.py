#!/usr/bin/env python3
"""Generate slim README.md from database.json and platform configs.

Detailed documentation lives on the site (abdess.github.io/retrobios/).
This script produces a concise landing page with download links and coverage.

Usage:
    python scripts/generate_readme.py [--db database.json] [--platforms-dir platforms/]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    compute_composition,
    count_catalog_matched,
    declared_root,
    github_token,
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    load_platform_registry,
    resolve_platform_cores,
    system_index,
    unique_emulator_profiles,
    write_if_changed,
)
from nativemode import check_label
import release_record
from siteguides import install_command
from verify import verify_platform


def _installer_words() -> object:
    """install.py read as a module, for the words its screen shows: the
    README named a line menu the one-liner never opens."""
    import importlib.util  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location(
        "install", Path(__file__).resolve().parent.parent / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The repository's profiles wherever the script is run from: a bare
# "emulators" read the working directory, and a run elsewhere counted 0 cores.
_EMULATORS_DIR = str(Path(__file__).resolve().parent.parent / "emulators")


def compute_coverage(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    data_registry: dict | None = None,
    emulators_dir: str = _EMULATORS_DIR,
) -> dict:
    config = load_platform_config(platform_name, platforms_dir)
    result = verify_platform(
        config,
        db,
        emulators_dir,
        data_dir_registry=data_registry,
    )
    sc = result.get("status_counts", {})
    ok = sc.get("ok", 0)
    untested = sc.get("untested", 0)
    missing = sc.get("missing", 0)
    total = result["total_files"]
    # An UNTESTED file the builder refuses (its declared hash contradicted on
    # a hash platform) is held, not packed.
    present = ok + untested - len(result.get("excluded_files", []))
    pct = (present / total * 100) if total > 0 else 0
    undeclared = result.get("undeclared_files", [])
    # Held is not packed: a file the platform has no folder for, or one below
    # a folder it lists flat, stays out of the pack the fraction describes.
    core_present = sum(
        1 for u in undeclared if u.get("in_repo") and u.get("in_pack", True)
    )
    core_missing = len(undeclared) - core_present
    # Files a profile marks unsourceable never reach the undeclared list, so
    # the gap they represent has to be counted back in.
    profiles = load_emulator_profiles(emulators_dir)
    unsourceable_names = {
        f.get("name", "")
        for emu in resolve_platform_cores(config, profiles)
        for f in (profiles.get(emu) or {}).get("files", []) or []
        if f.get("unsourceable")
    }
    core_unsourceable = len(unsourceable_names)
    missing_names = unsourceable_names | {
        u.get("name", "") for u in undeclared if not u.get("in_repo")
    }
    return {
        "platform": config.get("platform", platform_name),
        "total": total,
        "verified": ok,
        "untested": untested,
        "missing": missing,
        "missing_not_firmware": {
            category: len(dests)
            for category, dests in (result.get("missing_not_firmware") or {}).items()
        },
        "present": present,
        "percentage": pct,
        "core_present": core_present,
        "core_missing": core_missing,
        "core_unsourceable": core_unsourceable,
        "missing_names": missing_names,
        "unsourceable_names": unsourceable_names,
        "pack_files": present + core_present,
        "total_missing": missing + core_missing,
        "mode": config.get("verification_mode", "existence"),
        "details": result["details"],
        "config": config,
        "ground_truth": result.get(
            "ground_truth_coverage",
            {"with_validation": 0, "platform_only": total, "total": total},
        ),
    }


_REPO = Path(__file__).resolve().parent.parent
# The site and the README read the same coverage: the first generator to run
# stores it here and the second reads it back, instead of verifying every
# platform twice (about a minute of the site build).
COVERAGE_CACHE_DIR = _REPO / "tmp" / "coverage-cache"
_COVERAGE_CACHE_FORMAT = "2"


def _coverage_inputs(db_path: Path, platforms_dir: str, emulators_dir: str) -> str:
    """A digest of everything coverage is computed from.

    The database, the platform and emulator files, the code, the install
    manifests, the data directory revisions and the state of bios/ on disk:
    a change to any of them computes the coverage again.
    """
    import hashlib

    digest = hashlib.sha256(_COVERAGE_CACHE_FORMAT.encode())

    def add_file(path: Path) -> None:
        digest.update(str(path).encode() + b"\0")
        digest.update(path.read_bytes() if path.is_file() else b"<absent>")

    add_file(db_path.resolve())
    for root, pattern in ((Path(platforms_dir), "*"), (Path(emulators_dir), "*.yml"),
                          (_REPO / "scripts", "*.py"), (_REPO / "install", "*.json"),
                          (_REPO / "recipes", "*.json")):
        for path in sorted(p for p in root.resolve().rglob(pattern) if p.is_file()):
            add_file(path)
    for path in (_REPO / ".gitignore", _REPO / "_mame_clones.json",
                 _REPO / "data" / ".versions.json"):
        add_file(path)
    bios = _REPO / "bios"
    for path in sorted(bios.rglob("*")):
        if path.is_file():
            stat = path.stat()
            digest.update(f"{path.relative_to(bios)}\0{stat.st_size}\0{stat.st_mtime_ns}\n".encode())
    return digest.hexdigest()


def platform_coverages(
    platform_names: list[str],
    platforms_dir: str,
    db: dict,
    data_registry: dict | None = None,
    emulators_dir: str = _EMULATORS_DIR,
    db_path: str = "database.json",
    report: Callable[[str, dict], None] | None = None,
) -> dict[str, dict]:
    """compute_coverage for each platform, read from the cache when its
    inputs have not changed since a generator last stored it.

    A platform with no YAML is left out, as compute_coverage raises for it.
    ``report`` is called with each platform and its coverage.
    """
    # pickle, not JSON: the coverage holds sets and enums that JSON would
    # turn into lists and strings. The file is written by this function into
    # the repository's own tmp/, never downloaded.
    import pickle

    key = _coverage_inputs(Path(db_path), platforms_dir, emulators_dir)
    names = sorted(platform_names)
    cache = COVERAGE_CACHE_DIR / f"{key}.pickle"
    coverages: dict[str, dict] | None = None
    if cache.is_file():
        try:
            with cache.open("rb") as handle:
                stored = pickle.load(handle)
        except (OSError, EOFError, pickle.UnpicklingError) as exc:
            print(f"  coverage cache unreadable, computing again: {exc}", file=sys.stderr)
        else:
            if stored.get("platforms") == names:
                coverages = stored["coverages"]
                print(f"  coverage read from {cache.relative_to(_REPO)}")
    if coverages is None:
        coverages = {}
        for name in names:
            try:
                coverages[name] = compute_coverage(
                    name, platforms_dir, db, data_registry, emulators_dir=emulators_dir,
                )
            except FileNotFoundError as exc:
                print(f"  {name}: skipped ({exc})", file=sys.stderr)
        COVERAGE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        for stale in COVERAGE_CACHE_DIR.glob("*.pickle"):
            stale.unlink()
        scratch = cache.with_suffix(f".{os.getpid()}.tmp")
        with scratch.open("wb") as handle:
            pickle.dump({"platforms": names, "coverages": coverages}, handle,
                        protocol=pickle.HIGHEST_PROTOCOL)
        scratch.replace(cache)
    ordered = {name: coverages[name] for name in platform_names if name in coverages}
    if report:
        for name in names:
            if name in ordered:
                report(name, ordered[name])
    return ordered


def release_totals(platform_name: str, record: dict) -> tuple[int | None, int | None]:
    """Files and bytes of the pack the latest release serves for a platform.

    The Download link gives that release, so these are the figures a reader
    can check against an extraction. The install manifests describe what
    main would build today, which is a different pack as soon as a commit
    lands after the release. Returns (None, None) for a platform the release
    carries no pack for.
    """
    pack = release_record.pack_for(platform_name, record)
    if not pack:
        return None, None
    return pack["files"], pack["extracted_size"]


NO_PACK = "Use the command"


def asset_links(
    platform_name: str, record: dict, repo: str, label: str, attrs: str = "",
    button: Callable[[str, str], str] | None = None,
) -> str:
    """Markdown links to the files of a platform's pack in the recorded release.

    Written on the platform's get/ page only: every other surface links that
    page, whose address does not change with the release. A pack published
    whole gets one link labelled *label*. A pack in parts gets one link per
    part, since every part is needed, after the number of files to download:
    a reader who took one link for the pack extracted half of it. *repo* is
    the repository URL, *attrs* an attribute list put after each link, or
    *button* the function that draws each link as a button. Without a
    recorded release the link is the latest release page.
    """
    pack = release_record.pack_for(platform_name, record)
    tag = record.get("tag")
    assets = pack.get("assets") if pack else None
    def link(text: str, url: str) -> str:
        return button(text, url) if button else f"[{text}]({url}){attrs}"

    if not tag or not assets:
        return link(label, f"{repo}/releases/latest")
    urls = [f"{repo}/releases/download/{tag}/{asset}" for asset in assets]
    if len(urls) == 1:
        return link(label, urls[0])
    styled = bool(attrs or button)
    parts = [
        link(f"{'P' if styled else 'p'}art {number} of {len(urls)}", url)
        for number, url in enumerate(urls, 1)
    ]
    if styled:
        return f"{len(urls)} files to download, all needed: " + " ".join(parts)
    return f"{label}, {len(urls)} files, all needed: " + ", ".join(parts)


def download_links(
    platform_name: str, record: dict, label: str, attrs: str = "",
    button: Callable[[str, str], str] | None = None,
    site: str = "", platforms_dir: str = "platforms", page: str | None = None,
) -> str:
    """The download cell of a platform: its permanent get/ page.

    *record* is the release record reduced to the release_pack platforms
    (release_record.advertised). A platform with a pack in it gets *label*
    linked to its page, which lists the files of the current release. A
    platform marked release_pack but missing from the release, added since,
    gets "No ZIP yet". Any other platform is served by the installer, and
    the cell says so instead of staying empty. *site* is the site root the
    get/ address hangs from, or *page* the address itself as the site links
    it, and *attrs* and *button* style the link.
    """
    page = page or release_record.get_page(platform_name, site)
    def link(text: str) -> str:
        return button(text, page) if button else f"[{text}]({page}){attrs}"

    if (load_platform_registry(platforms_dir).get(platform_name) or {}).get("release_pack") is not True:
        return link(NO_PACK)
    pack = release_record.pack_for(platform_name, record)
    if record.get("tag") and not (pack and pack.get("assets")):
        return f"No ZIP yet: {link(NO_PACK.lower())}"
    return link(label)


def extract_targets(platforms_dir: str) -> list[tuple[str, str]]:
    """(display name, folder) per registered platform, where its pack extracts.

    Read from the registry so the README, the site and the pack guide answer
    from one place. Sorted by display name.
    """
    rows = [
        (load_platform_config(key, platforms_dir).get("platform", key), entry["extract_to"])
        for key, entry in load_platform_registry(platforms_dir).items()
        if entry.get("extract_to")
    ]
    return sorted(rows, key=lambda row: row[0].casefold())


def own_root(config: dict) -> str:
    """The folder a pack written from an empty base_destination starts with.

    RetroDECK writes bios/ in front of its files, the MinUI family hands its
    cores folders below Bios/.
    """
    root = declared_root(config)
    if root:
        return root
    tops = {directory.split("/", 1)[0] for directory in config.get("core_system_dirs") or {}}
    return tops.pop() if len(tops) == 1 else "bios"


def extract_notes(platforms_dir: str, released_only: bool = False) -> list[str]:
    """A pack whose entries carry their own root extracts above the BIOS folder.

    *released_only* keeps the platforms a release publishes a pack for.
    """
    folders = dict(extract_targets(platforms_dir))
    registry = load_platform_registry(platforms_dir)
    notes = []
    for key in sorted(registry):
        if released_only and registry[key].get("release_pack") is not True:
            continue
        config = load_platform_config(key, platforms_dir)
        display = config.get("platform", key)
        if config.get("base_destination") == "" and display in folders:
            notes.append(
                f"The {display} pack holds its own `{own_root(config)}/` folder."
                f" Unzip it into `{folders[display]}`."
            )
    return notes


def _extract_cells(platforms_dir: str) -> dict[str, str]:
    """The download table's "Extract to" cell, by display name."""
    return {display: f"`{folder}`" for display, folder in extract_targets(platforms_dir)}


def _paragraphs(texts: list[str]) -> list[str]:
    return [line for text in texts for line in ("", text)]


def download_table(
    coverages: dict,
    archived: set[str],
    extract_paths: dict[str, str],
    record: dict,
) -> list[str]:
    """One row per platform: what its released pack holds and where it extracts."""
    lines = [
        "| Platform | Files | Extracted size | Extract to | Download |",
        "|----------|------:|---------------:|-----------|----------|",
    ]
    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        if name in archived:
            display = f"{display} *"
        files, size = release_totals(name, record)
        lines.append(
            f"| {display} | {f'{files:,}' if files else '-'} |"
            f" {format_size(size) if size else '-'} |"
            f" {extract_paths.get(cov['platform'], '')} |"
            f" {download_links(name, record, 'Download', site=SITE_URL)} |"
        )
    return lines


def no_pack_line() -> str:
    """Why some rows read "Use the command", in one sentence."""
    return (
        "ZIPs are made for the setups most people download. The others read"
        f" \"{NO_PACK}\": the installer above installs every file for them and"
        " checks each one, and `--dry-run` shows what it would install"
        f" ([why no ZIP]({SITE_URL}wiki/faq/#why-is-there-no-zip-for-my-setup))."
    )


def _names_list(coverages: dict) -> str:
    """The platforms' names in reading order, the last after "and"."""
    names = sorted(c["platform"] for c in coverages.values())
    return ", ".join(names[:-1]) + f", and {names[-1]}" if len(names) > 1 else "".join(names)


def collection_line(total_files: int, comp: dict) -> str:
    """The size of the whole collection, said as such.

    Printed bare beside the download links it read as the content of one
    pack, and a complete extraction looked like a broken one.
    """
    return (
        f"- **{total_files:,} files in the collection**, each with its SHA1,"
        " MD5, SHA256, CRC32 and Adler-32 fingerprints:"
        f" {comp['systems']['files']:,} system files,"
        f" {comp['arcade']['files']:,} arcade ROM sets,"
        f" {comp['game_data']['files']:,} game and engine data files."
        " That is every platform and emulator together, so no pack holds"
        " them all: each carries what its own emulators load, counted in"
        " the download table"
    )


def format_size(size: int) -> str:
    """Human-readable pack size."""
    if size >= 1024**3:
        return f"{size / 1024**3:.1f} GB"
    return f"{size / 1024**2:.0f} MB"


SITE_URL = "https://abdess.github.io/retrobios/"
REPO_PATH = "../.."
REPO = "Abdess/retrobios"
# GitHub's "Add file > Upload files" page for bios/: a browser upload by
# someone without write access lands on a fork and opens a pull request.
UPLOAD_URL = f"https://github.com/{REPO}/upload/main/bios"


def _existing_contributor_block(readme_path: str = "README.md") -> list[str]:
    """The contributors already published, read back from the file.

    The section is the one part of this document that comes from the network.
    A refused or rate-limited request used to leave the list empty, which
    silently deleted the section from a published README and put the local
    result permanently at odds with what the freshness check regenerates.
    Keeping what is already there makes an offline run additive-only.
    """
    try:
        with open(readme_path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return []
    start = text.find("## Contributors")
    if start == -1:
        return []
    rest = text[start:].splitlines()
    block = []
    for line in rest[1:]:
        if line.startswith("## "):
            break
        block.append(line)
    while block and not block[-1].strip():
        block.pop()
    return ["## Contributors"] + block if block else []


def fetch_contributors() -> list[dict]:
    """Fetch contributors from GitHub API, exclude bots."""
    import urllib.error
    import urllib.request

    url = f"https://api.github.com/repos/{REPO}/contributors"
    headers = {"User-Agent": "retrobios-readme/1.0"}
    token = github_token()
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        owner = REPO.split("/")[0]
        return [
            c
            for c in data
            if not c.get("login", "").endswith("[bot]")
            and c.get("type") == "User"
            and c.get("login") != owner
        ]
    except (urllib.error.URLError, urllib.error.HTTPError):
        return []


_CATALOG_LABELS = {"redump": "Redump", "no-intro": "No-Intro", "tosec": "TOSEC"}


def _catalog_matched_line(db: dict) -> list[str]:
    """Bullet line for files matched to dump-preservation catalogs."""
    matched = count_catalog_matched(db)
    if not matched:
        return []
    sources: set[str] = set()
    for entry in db.get("files", {}).values():
        sources.update(entry.get("provenance") or ())
    system_files = compute_composition(db)["systems"]["files"]
    labels = ", ".join(_CATALOG_LABELS.get(s, s) for s in sorted(sources))
    return [
        f"- **{matched:,} of {system_files:,} system files** matched to"
        f" dump-preservation catalogs ({labels}). Arcade sets and engine data"
        f" fall outside what those catalogs index"
    ]


def generate_readme(db: dict, platforms_dir: str, db_path: str = "database.json") -> str:
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    platform_names = list_registered_platforms(platforms_dir, include_archived=True)

    from common import load_data_dir_registry

    data_registry = load_data_dir_registry(platforms_dir)

    coverages = platform_coverages(platform_names, platforms_dir, db, data_registry,
                                   db_path=db_path)

    profiles = unique_emulator_profiles(
        load_emulator_profiles("emulators", skip_aliases=False)
    )
    emulator_count = len(profiles)
    comp = compute_composition(db)
    missing_total = len(set().union(*(c["missing_names"] for c in coverages.values())))
    # "Not in the collection yet" implies somebody could still put it there.
    # Most of this figure cannot be: per-user registration keys, slots the
    # emulator expects the user to fill, dumps nobody has made. Counting those
    # beside genuinely acquirable files overstates what is actionable, so the
    # two are reported apart.
    unsourceable_total = len(
        set().union(*(c["unsourceable_names"] for c in coverages.values()))
    )
    acquirable_total = missing_total - unsourceable_total

    system_ids = system_index(profiles)

    lines = [
        '<p align="center">',
        "  <picture>",
        '    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/banner-dark.svg">',
        '    <img src=".github/assets/banner-light.svg" alt="RetroBIOS" width="400">',
        "  </picture>",
        "</p>",
        "",
        '<p align="center">',
        '  <a href="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml">'
        '<img src="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml/badge.svg" alt="Site"></a>',
        "</p>",
        "",
        f"BIOS and firmware files for {_names_list(coverages)}.",
        "",
        "A pack holds the files its emulators read, as their source code names"
        " them, and leaves out what the emulators install themselves.",
        "",
        "## Quick install",
        "",
        "Copy one command into your terminal:",
        "",
        "```bash",
        "# Linux / macOS / Steam Deck",
        install_command("sh"),
        "",
        "# Windows (PowerShell)",
        install_command("powershell"),
        "",
        "# Android (Termux, after pkg install python and termux-setup-storage)",
        install_command("sh"),
        "",
        "# SD card mounted on a PC: a muOS, KNULLI, ROCKNIX, Onion, spruceOS or MinUI card",
        "# is found by itself. For another card, --dest is its BIOS folder",
        "# (RetroArch on Switch: retroarch/cores/system, on Android: RetroArch/system)",
        install_command("sh", "--platform retroarch --dest /path/to/sdcard/retroarch/cores/system"),
        "",
        "# Options in PowerShell: anything after | iex goes to iex, so the script runs as a block",
        install_command("powershell", "--check"),
        "```",
        "",
        "The script opens a full-screen installer, driven with the arrow keys and Enter, or with a"
        " controller on a handheld. It finds your setup and its BIOS folder, downloads only the missing"
        " files and checks each one. It can also copy the BIOS files from your old SD card.",
        f"Every option, and what the installer detects and writes, is on the [installer page]({SITE_URL}wiki/installer/#passing-options).",
        "",
        "## Download BIOS packs",
        "",
        "A pack holds everything its platform runs: its own BIOS list plus every file its emulator cores load. Pick your platform, download the ZIP, extract to the BIOS path. Each Download link is a page that keeps its address from one release to the next. The installer above does the same file by file: its screen installs everything, or fewer under **" + _installer_words().TUI_SYSTEMS_ROW + "**, and `--system`, `--core`, `--region` and `--target` make the same choice without questions. For a bare minimum, build your own pack below.",
        "",
        "A pack over 2 GB comes in several parts (`Pack.part1of2.zip`,"
        " `Pack.part2of2.zip`), and every part is needed. Each part is an"
        " ordinary ZIP: extract them all into the same folder.",
        "",
        "Every release ships `SHA256SUMS.txt` and a detached signature of it,"
        " checkable against `allowed_signers` in this repository:"
        " [verifying a release]"
        "(https://abdess.github.io/retrobios/wiki/release-process/"
        "#verifying-a-release).",
        "",
        "The Files column counts what a pack holds once extracted, the figure a"
        " file manager shows for the folder. It differs from one platform to"
        " the next because a pack carries only what that platform's emulators"
        " load. The size is what the files occupy once extracted, and the ZIP"
        " itself downloads smaller.",
        "",
    ]

    # Where the pack itself is extracted, which is not always the BIOS folder:
    # a pack whose entries already carry their own root (RetroDECK) extracts
    # one level above it.
    extract_paths = _extract_cells(platforms_dir)
    archived = {
        name
        for name, entry in load_platform_registry(platforms_dir).items()
        if entry.get("status") == "archived"
    }

    lines.extend(
        download_table(
            coverages, archived, extract_paths,
            release_record.load_advertised(platforms_dir=platforms_dir),
        )
    )
    lines.extend(["", no_pack_line()])

    lines.extend(_paragraphs(extract_notes(platforms_dir, released_only=True)))
    if archived:
        lines.extend(
            [
                "",
                "\\* Archived: the configuration is kept and the installer serves it,"
                " but upstream is no longer scraped on a schedule.",
            ]
        )

    lines.extend(
        [
            "",
            "## What's included",
            "",
            "BIOS, firmware, and system files for consoles from Atari to PlayStation 3.",
            "These are the files an emulator loads from disk instead of"
            " carrying inside itself. Some are required to boot a system,"
            " others improve accuracy or unlock a feature, and the packs carry"
            " both.",
            "",
            "Each file is checked the way your platform checks it. Most compare"
            " a checksum, the fingerprint of a file's contents, which catches a"
            " corrupt or unexpected copy. RetroArch, Lakka and RetroPie check"
            " that the file is present under its name without reading its"
            " contents (`path_is_valid` in RetroArch's `core_info.c`), and"
            " MinUI, NextUI and MyMinUI hand each core its folder without"
            " opening a file in it: the"
            " Coverage table says which applies to you. Independently of that,"
            " the collection records five fingerprints per file, and wherever"
            " an emulator's code states an expected size or hash, that value is"
            " read from its source and rechecked here.",
            "",
            (
                f"- **{acquirable_total:,} files** the platforms' emulators load"
                f" are still to be found, and {unsourceable_total:,} more cannot"
                f" be sourced at all (per-user keys, user-filled slots, dumps"
                f" nobody has made). Both are named in the"
                f" [gap analysis]({SITE_URL}gaps/)"
                if missing_total
                else "- **Nothing missing**: every file the platforms'"
                " emulators load is in the collection"
            ),
            f"- **{len(coverages)} platforms** supported with platform-specific verification",
            f"- **{emulator_count} emulators** profiled from source (RetroArch cores + standalone)",
            f"- **{len(system_ids)} systems** handled by those emulators (NES, SNES, PlayStation, Saturn, Dreamcast, ...)",
            collection_line(total_files, comp),
            *_catalog_matched_line(db),
            f"- **{format_size(total_size)}** for the whole collection",
            "",
            "## Supported systems",
            "",
        ]
    )

    # Show well-known systems for SEO, link to full list
    well_known = [
        "NES",
        "SNES",
        "Nintendo 64",
        "GameCube",
        "Wii",
        "Game Boy",
        "Game Boy Advance",
        "Nintendo DS",
        "Nintendo 3DS",
        "Switch",
        "PlayStation",
        "PlayStation 2",
        "PlayStation 3",
        "PSP",
        "PS Vita",
        "Mega Drive",
        "Saturn",
        "Dreamcast",
        "Game Gear",
        "Master System",
        "Neo Geo",
        "Atari 2600",
        "Atari 7800",
        "Atari Lynx",
        "Atari ST",
        "MSX",
        "PC Engine",
        "TurboGrafx-16",
        "ColecoVision",
        "Intellivision",
        "Commodore 64",
        "Amiga",
        "ZX Spectrum",
        "Arcade (MAME)",
    ]
    lines.extend(
        [
            ", ".join(well_known) + f", and {len(system_ids) - len(well_known)}+ more.",
            "",
            f"Full list with per-file details: **[{SITE_URL}]({SITE_URL})**",
            "",
            "## Coverage",
            "",
            "| Platform | On its BIOS list | Files its emulators load | Checked by |",
            "|----------|-----------------:|-------------------------:|------------|",
        ]
    )

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = f"{cov['platform']} *" if name in archived else cov["platform"]
        checked = check_label(cov["mode"], cov["config"].get("hash_rule"))
        core_total = (
            cov["core_present"] + cov["core_missing"] + cov["core_unsourceable"]
        )
        core_cell = f"{cov['core_present']:,}/{core_total:,}" if core_total else "-"
        lines.append(
            f"| {display} | {cov['present']:,}/{cov['total']:,} |"
            f" {core_cell} | {checked} |"
        )

    lines.extend(
        [
            "",
            "Each fraction is what the pack has over what is needed, counting"
            " required and optional files alike since both ship. The first"
            " column is the BIOS list the platform publishes. The second counts"
            " files its emulators load that this list never mentions, found by"
            " reading their source code, and it is routinely several times"
            " larger. A short fraction means files are still missing, and they"
            " are named in the"
            f" [gap analysis]({SITE_URL}gaps/).",
            "That second number is a floor, not a ceiling: an emulator that"
            " accepts any file handed to it names none in its code, so nothing"
            " there can be counted.",
            "Checked by is the test your platform runs on its own, replicated"
            " here from its source code, so the result matches what you would"
            f" see in the frontend ([how each one works]({SITE_URL}wiki/verification-modes/)).",
            "",
            "## Build your own pack",
            "",
            "Clone the repo and generate packs for any platform, emulator, or system:",
            "",
            "```bash",
            "# The pack of a platform, as released",
            "python scripts/generate_pack.py --platform retroarch --output-dir dist/",
            "python scripts/generate_pack.py --platform batocera --output-dir dist/",
            "",
            "# Single emulator or system",
            "python scripts/generate_pack.py --emulator dolphin",
            "python scripts/generate_pack.py --system sony-playstation-2",
            "",
            "# One region, best first, one file per system and region",
            "python scripts/generate_pack.py --platform retroarch --region us,eu,jp",
            "python scripts/generate_pack.py --platform retroarch --region us --one-per-slot",
            "",
            "# Firmware only: the game data a list or a core names is left out, each file named",
            "python scripts/generate_pack.py --platform emuelec --no-game-data",
            "",
            "# The bare minimum: only the files each core needs to start",
            "python scripts/generate_pack.py --platform batocera --required-only",
            "",
            "# List available emulators and systems",
            "python scripts/generate_pack.py --list-emulators",
            "python scripts/generate_pack.py --list-systems",
            "",
            "# Coverage of this repository's collection per platform, emulator or system",
            "# (it reads database.json and bios/: for your own BIOS folder, run the installer with --check)",
            "python scripts/verify.py --all",
            "python scripts/verify.py --platform batocera",
            "python scripts/verify.py --emulator flycast",
            "python scripts/verify.py --platform retroarch --verbose  # emulator ground truth",
            "```",
            "",
            "Requires Python 3.9 or newer and `pyyaml`. The one-line installer alone runs on Python 3.8.",
            "",
            "## Documentation site",
            "",
            f"The [documentation site]({SITE_URL}) provides:",
            "",
            "- **Per-platform pages** with file-by-file verification status and hashes",
            "- **Per-emulator profiles** with source code references for every file",
            "- **Per-system pages** showing which emulators and platforms cover each console",
            "- **Gap analysis** identifying missing files and undeclared core requirements",
            f"- **Cross-reference** mapping files across {len(coverages)} platforms and {emulator_count} emulators",
            "- **Versioned data access** through JSON, CSV and SQLite exports with published SHA-256 checksums",
            "",
            "## How it works",
            "",
            "A platform's BIOS list and an emulator's code are maintained"
            " separately. Each list is compared with the emulator source code,"
            " file by file where a profile exists, and where the two differ the"
            " code decides.",
            "",
            "Hashes document what emulator code loads and accepts, not dump"
            " provenance. That boundary, and how it relates to preservation"
            " catalogs such as No-Intro, is drawn in the"
            f" [technical questions]({SITE_URL}wiki/technical-faq/"
            "#are-these-files-verified-against-original-hardware-dumps).",
            "",
            "1. **Read emulator source code**: trace every file the code loads, its expected hash and size",
            "2. **Cross-reference with platforms**: match against what each platform declares",
            "3. **Build packs**: include baseline files plus what each platform's cores need",
            "4. **Verify**: run platform-native checks and emulator-level validation",
            "",
        ]
    )

    contributors = fetch_contributors()
    if not contributors:
        # The request failed. Republish what is already there rather than
        # dropping the section: losing it is a worse answer than a stale list.
        kept = _existing_contributor_block("README.md")
        if kept:
            print("contributors: request failed, keeping the published list")
            lines.extend(kept + [""])
    if contributors:
        lines.extend(
            [
                "## Contributors",
                "",
            ]
        )
        for c in contributors:
            login = c["login"]
            avatar = c.get("avatar_url", "")
            url = c.get("html_url", f"https://github.com/{login}")
            lines.append(
                f'<a href="{url}"><img src="{avatar}" width="50" alt="{login}"'
                f' title="{login}"></a>'
            )
        lines.append("")

    lines.extend(
        [
            "",
            "## Community tools",
            "",
            "- [BIOS Preservation Tool](https://github.com/monster-penguin/BIOS-Preservation-Tool)"
            " by [monster-penguin](https://github.com/monster-penguin)"
            " - scan, verify, and stage your own BIOS collection"
            " using RetroBIOS hash metadata",
            "",
            "## Contributing",
            "",
            "See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.",
            "",
            "## License",
            "",
            "The scripts and tooling are released under the [MIT License](LICENSE).",
            "The BIOS and firmware files are not covered by that license: they are"
            " third-party system software, preserved and provided for personal"
            " backup, archival, and interoperability with emulation software."
            " [NOTICE](NOTICE) sets out their status and how to ask for a file"
            " to be removed.",
            f"The reasoning, and where it is weakest, is in"
            f" [the project's legal position]({SITE_URL}wiki/legal/).",
            "",
            f"*Auto-generated on {ts}*",
        ]
    )

    return "\n".join(lines) + "\n"


def contributing_text(
    link: Callable[[str], str], title: str, site_words: str
) -> str:
    """The contribution guide, one text for the repository and the site.

    Two copies drifted apart: four steps to add a platform here, five on the
    site. *link* renders a site page (absolute URL for the README, relative
    .md for the site); *site_words* names the site from where the text is read.
    """
    return f"""{title}

## Add a BIOS file

Have a file the collection lacks? Add it from the browser. It is checked on arrival.

[Upload it into `bios/`]({UPLOAD_URL}), 25 MB at most per file. GitHub
writes it to a fork and opens the pull request.

The files most wanted are on [what the packs do not hold]({link("gaps")}). The
[dump provenance]({link("provenance")}) page lists catalogued dumps still
missing from the collection, with their hashes. A file matching one of those is
the most useful contribution.

## What happens next

1. CI hashes the file and looks it up in every platform list and emulator
   profile. For a file it recognises, it names the folder holding the other
   files of its system. The report is in the summary of the pull request's
   Validation run.
2. The file can be moved to that folder in the same pull request. A file whose
   hash differs from the one already held under its name goes to that folder's
   `.variants/`.

From a clone, the file goes to `bios/Manufacturer/Console/filename`, and
`python scripts/validate_pr.py path/to/file` names that folder for a file still
outside `bios/`. A file over the browser's 25 MB limit goes in that way.

## Add a platform

1. Write a scraper in `scripts/scraper/` (inherit `BaseScraper`)
2. Read the platform's upstream source to determine how it checks BIOS files
3. Register it in `platforms/_registry.yml`
4. Generate the platform YAML and test: `python scripts/verify.py --platform <name>`

Full walkthrough: [adding a platform]({link("wiki/adding-a-platform")}).

## Add an emulator profile

1. Clone the emulator's source code, upstream and libretro port
2. Trace the file loading from the entry point, not from a keyword grep
3. Document every file the code loads, with a `source_ref` line reference
4. Write the YAML to `emulators/<name>.yml`
5. Test: `python scripts/cross_reference.py --emulator <name>`

Full walkthrough: [profiling guide]({link("wiki/profiling")}).

## File conventions

- `bios/Manufacturer/Console/filename` for canonical files
- `bios/Manufacturer/Console/.variants/filename.sha1prefix` for alternate versions
- A file too large for git goes to the `large-files` GitHub release and its
  path into `.gitignore`, the list that decides what is served from the release
- Trees addressed by path are kept out of deduplication (`NODEDUP_DIRS` in
  `scripts/dedup.py`)
- Two paths differing only by case break clones on Windows and macOS,
  and `tests/test_no_case_collisions.py` enforces this

## Before opening a PR

A pull request that only adds files under `bios/` needs none of this: the
validation above is its check. For code, profiles or platform files, these are
the checks CI runs on a pull request (Python 3.12 or newer):

```bash
pip install pyyaml "jsonschema[format-nongpl]" markdown
python scripts/validate_pr.py --changed          # the BIOS files the branch adds
python scripts/validate_schemas.py --source-only # profiles and platform files
python scripts/profile_sync.py --added --base upstream/main --strict  # each profile the branch adds
python scripts/refresh_data_dirs.py  # data directories the pack-building tests read
python scripts/generate_site.py       # the pages the site tests read
python -m unittest discover -s tests -t .
```

`upstream` is this repository as a remote of your fork
(`git remote add upstream https://github.com/Abdess/retrobios`). A profile you
only edit is not held to `--strict`: its older refs are reviewed by hand.

The full pipeline is not needed for a contribution: it rebuilds every pack
in `dist/`, which is why maintainers run it before a release.

## PR validation

CI computes SHA1/MD5/CRC32 for every new file, checks them against the platform
configs, validates the YAML against the schemas, confronts each added profile
with its upstream source and runs the test suite. The BIOS report goes to the
summary of the Validation run, and also to a comment when the branch lives in
this repository: a fork's pull request runs with a read-only token.

Contributors who add platform support are credited in the README,
{site_words}, and in the BIOS packs.
"""


def generate_contributing() -> str:
    return contributing_text(
        lambda page: f"{SITE_URL}{page}/",
        "# Contributing to RetroBIOS",
        "on the documentation site",
    )


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Generate slim README.md")
    parser.add_argument(
        "--db", default="database.json",
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    args = parser.parse_args()

    import contextlib

    from common import load_data_dir_registry
    from refresh_data_dirs import hold_data_dirs

    db = load_database(args.db)

    # Coverage resolves against data/: a refresh swapping a tree mid-read
    # published counts taken from half of it.
    with contextlib.ExitStack() as held:
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
        readme = generate_readme(db, args.platforms_dir, args.db)
    status = "Generated" if write_if_changed("README.md", readme) else "Unchanged"
    print(f"{status} ./README.md")

    contributing = generate_contributing()
    status = (
        "Generated"
        if write_if_changed("CONTRIBUTING.md", contributing)
        else "Unchanged"
    )
    print(f"{status} ./CONTRIBUTING.md")


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
