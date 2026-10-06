#!/usr/bin/env python3
"""Generate slim README.md from database.json and platform configs.

Detailed documentation lives on the MkDocs site (abdess.github.io/retrobios/).
This script produces a concise landing page with download links and coverage.

Usage:
    python scripts/generate_readme.py [--db database.json] [--platforms-dir platforms/]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    compute_composition,
    count_catalog_matched,
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    load_platform_registry,
    resolve_platform_cores,
    unique_emulator_profiles,
    write_if_changed,
)
import release_record
from verify import verify_platform


# The repository's profiles wherever the script is run from: a bare
# "emulators" read the working directory, and a run elsewhere counted 0 cores.
_EMULATORS_DIR = str(Path(__file__).resolve().parent.parent / "emulators")


def compute_coverage(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    data_registry: dict | None = None,
    supplemental_names: set[str] | None = None,
    emulators_dir: str = _EMULATORS_DIR,
) -> dict:
    config = load_platform_config(platform_name, platforms_dir)
    result = verify_platform(
        config,
        db,
        emulators_dir,
        data_dir_registry=data_registry,
        supplemental_names=supplemental_names,
    )
    sc = result.get("status_counts", {})
    ok = sc.get("ok", 0)
    untested = sc.get("untested", 0)
    missing = sc.get("missing", 0)
    total = result["total_files"]
    present = ok + untested
    pct = (present / total * 100) if total > 0 else 0
    undeclared = result.get("undeclared_files", [])
    core_present = sum(1 for u in undeclared if u.get("in_repo"))
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


def extract_notes(platforms_dir: str) -> list[str]:
    """A pack whose entries carry their own root extracts above the BIOS folder."""
    folders = dict(extract_targets(platforms_dir))
    notes = []
    for key in sorted(load_platform_registry(platforms_dir)):
        config = load_platform_config(key, platforms_dir)
        display = config.get("platform", key)
        if config.get("base_destination") == "" and display in folders:
            notes.append(
                f"The {display} pack already carries its own `bios/` folder, so it"
                f" extracts into `{folders[display]}` rather than into the BIOS folder."
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
            f" [Download]({RELEASE_URL}) |"
        )
    return lines


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
RELEASE_URL = "../../releases/latest"
REPO = "Abdess/retrobios"


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
    token = os.environ.get("GITHUB_TOKEN", "")
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
        f" dump-preservation catalogs ({labels}); arcade sets and engine data"
        f" fall outside what those catalogs index"
    ]


def generate_readme(db: dict, platforms_dir: str) -> str:
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    size_mb = total_size / (1024 * 1024)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    platform_names = list_registered_platforms(platforms_dir, include_archived=True)

    from common import load_data_dir_registry
    from cross_reference import _build_supplemental_index

    data_registry = load_data_dir_registry(platforms_dir)
    suppl_names = _build_supplemental_index()

    coverages = {}
    for name in platform_names:
        try:
            coverages[name] = compute_coverage(
                name, platforms_dir, db, data_registry, suppl_names
            )
        except FileNotFoundError:
            pass

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

    system_ids: set[str] = set()
    for p in profiles.values():
        system_ids.update(p.get("systems", []))

    lines = [
        '<p align="center">',
        '  <img src=".github/assets/banner.png" alt="RetroBIOS" width="400">',
        "</p>",
        "",
        '<p align="center">',
        '  <a href="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml">'
        '<img src="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml/badge.svg" alt="Site"></a>',
        "</p>",
        "",
        f"Complete BIOS and firmware packs for "
        f"{', '.join(c['platform'] for c in sorted(coverages.values(), key=lambda x: x[
                    'platform'
                ])[:-1])}"
        f", and {sorted(coverages.values(), key=lambda x: x[
                'platform'
            ])[-1]['platform']}.",
        "",
        f"Pick your platform below and extract the pack: it carries every file"
        f" its emulators load, read from their source code. Nothing to"
        f" configure, nothing to hunt down.",
        "",
        "## Quick Install",
        "",
        "Copy one command into your terminal:",
        "",
        "```bash",
        "# Linux / macOS / Steam Deck",
        "curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh",
        "",
        "# Windows (PowerShell)",
        "irm https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1 | iex",
        "",
        "# Android (Termux, after pkg install python and termux-setup-storage)",
        "curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh",
        "",
        "# Handheld (SD card mounted on PC)",
        "curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh -s -- --platform retroarch --dest /path/to/sdcard",
        "```",
        "",
        "The script auto-detects your platform, downloads only missing files, and verifies checksums.",
        "",
        "## Download BIOS packs",
        "",
        "One pack per platform, and it holds everything the platform runs: its own BIOS list plus every file its emulator cores load. Pick your platform, download the ZIP, extract to the BIOS path. The installer above does the same file by file, and `--target` narrows it to one machine; for a region or a bare minimum, build your own pack below.",
        "Files is how many the pack holds once extracted, the figure a file"
        " manager shows for the folder. It differs from one platform to the"
        " next because a pack carries only what that platform's emulators"
        " load."
        " The size is what the files occupy once extracted; the ZIP itself"
        " downloads smaller.",
        "",
        "A pack over 2 GB comes in several parts, and every part is needed."
        " How to open them depends on their name:",
        "",
        "- `Pack.part1of2.zip`, `Pack.part2of2.zip`: each part is an ordinary"
        " ZIP. Extract them all into the same folder.",
        "- `Pack.zip.001`, `Pack.zip.002` (releases up to v2026.09.04): slices"
        " of one ZIP, none of which opens on its own. Put them in one folder"
        " and open the `.001` with 7-Zip or PeaZip, or join them first with"
        " `cat Pack.zip.0* > Pack.zip` on Linux and macOS,"
        " `cmd /c copy /b Pack.zip.001+Pack.zip.002 Pack.zip` on Windows.",
        "",
        "Every release ships `SHA256SUMS.txt` and a detached signature of it,"
        " checkable against `allowed_signers` in this repository:"
        " [verifying a release]"
        "(https://abdess.github.io/retrobios/wiki/release-process/"
        "#verifying-a-release).",
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
            coverages, archived, extract_paths, release_record.load_record()
        )
    )

    lines.extend(_paragraphs(extract_notes(platforms_dir)))
    if archived:
        lines.extend(
            [
                "",
                "\\* Archived: the configuration is kept and packs are still built,"
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
            " others improve accuracy or unlock a feature; the packs carry"
            " both.",
            "",
            "Each file is checked the way your platform checks it. Most compare"
            " a checksum, the fingerprint of a file's contents, which catches a"
            " corrupt or unexpected copy. RetroArch, Lakka and RetroPie only"
            " look for the filename, because that is all their code does: the"
            " Coverage table says which applies to you. Independently of that,"
            " the collection records five fingerprints per file, and wherever"
            " an emulator's code states an expected size or hash, that value is"
            " read from its source and rechecked here.",
            "",
            (
                f"- **{acquirable_total} files** the platforms' emulators load"
                f" are still to be found, and {unsourceable_total} more cannot"
                f" be sourced at all (per-user keys, user-filled slots, dumps"
                f" nobody has made); both are named in the"
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
            f"- **{size_mb:.0f} MB** total collection size",
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

    mode_labels = {
        "md5": "MD5 hash",
        "sha1": "SHA1 hash",
        "existence": "file presence",
    }

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = f"{cov['platform']} *" if name in archived else cov["platform"]
        checked = mode_labels.get(cov["mode"], cov["mode"])
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
            "# List available emulators and systems",
            "python scripts/generate_pack.py --list-emulators",
            "python scripts/generate_pack.py --list-systems",
            "",
            "# Verify your BIOS collection",
            "python scripts/verify.py --all",
            "python scripts/verify.py --platform batocera",
            "python scripts/verify.py --emulator flycast",
            "python scripts/verify.py --platform retroarch --verbose  # emulator ground truth",
            "```",
            "",
            "Only dependency: Python 3 + `pyyaml`.",
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
            "Documentation and metadata can drift from what emulators actually load.",
            "To keep packs accurate, platform lists are checked against emulator"
            " source code, file by file where a profile exists; when the two"
            " disagree, the code wins.",
            "",
            "Hashes document what emulator code loads and accepts, not dump"
            " provenance; that boundary, and how it relates to preservation"
            " catalogs such as No-Intro, is drawn in the"
            f" [FAQ]({SITE_URL}wiki/faq/"
            "#are-these-files-verified-against-original-hardware-dumps).",
            "",
            "1. **Read emulator source code** - trace every file the code loads, its expected hash and size",
            "2. **Cross-reference with platforms** - match against what each platform declares",
            "3. **Build packs** - include baseline files plus what each platform's cores need",
            "4. **Verify** - run platform-native checks and emulator-level validation",
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
            f"The reasoning, and where it is weakest, is in the"
            f" [FAQ]({SITE_URL}wiki/faq/#is-this-legal).",
            "",
            f"*Auto-generated on {ts}*",
        ]
    )

    return "\n".join(lines) + "\n"


def contributing_text(link, title: str, site_words: str) -> str:
    """The contribution guide, one text for the repository and the site.

    Two copies drifted apart: four steps to add a platform here, five on the
    site. *link* renders a site page (absolute URL for the README, relative
    .md for MkDocs); *site_words* names the site from where the text is read.
    """
    return f"""{title}

## Add a BIOS file

1. Fork this repository
2. Place the file in `bios/Manufacturer/Console/filename`
3. Variants (alternate hashes for the same file): `bios/Manufacturer/Console/.variants/`
4. Open a Pull Request - hashes are verified automatically and reported as a comment

The [dump provenance]({link("provenance")}) page lists catalogued dumps still
missing from the collection, with their hashes. A file matching one of those is
the most useful contribution.

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
- Files >50 MB go in GitHub release assets (`large-files` release)
- RPG Maker and ScummVM directories are excluded from deduplication
- Two paths differing only by case break clones on Windows and macOS;
  `tests/test_no_case_collisions.py` enforces this

## Before opening a PR

```bash
python -m unittest discover tests
python scripts/pipeline.py --offline
```

## PR validation

CI computes SHA1/MD5/CRC32 for every new file, checks them against the platform
configs, validates the YAML against the schemas, runs the test suite, and posts
a report on the PR.

Contributors who add platform support are credited in the README,
{site_words}, and in the BIOS packs.
"""


def generate_contributing() -> str:
    return contributing_text(
        lambda page: f"{SITE_URL}{page}/",
        "# Contributing to RetroBIOS",
        "on the documentation site",
    )


def main():
    parser = argparse.ArgumentParser(description="Generate slim README.md")
    parser.add_argument("--db", default="database.json")
    parser.add_argument("--platforms-dir", default="platforms")
    args = parser.parse_args()

    db = load_database(args.db)

    readme = generate_readme(db, args.platforms_dir)
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
    main()
