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

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    GAME_DATA_TOPS,
    compute_composition,
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    load_platform_registry,
    resolve_platform_cores,
    unique_emulator_profiles,
    write_if_changed,
)
from verify import verify_platform


def compute_coverage(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    data_registry: dict | None = None,
    supplemental_names: set[str] | None = None,
) -> dict:
    config = load_platform_config(platform_name, platforms_dir)
    result = verify_platform(
        config,
        db,
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
    profiles = load_emulator_profiles("emulators")
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


def manifest_totals(
    platform_name: str, install_dir: str = "install"
) -> tuple[int | None, int | None]:
    """Files and bytes a platform's pack ships, from its install manifest.

    The manifest is written when packs are built, so it reflects the real
    pack contents (platform list, core complement and data directories).
    Returns (None, None) when no manifest exists yet.
    """
    path = os.path.join(install_dir, f"{platform_name}.json")
    if not os.path.exists(path):
        return None, None
    try:
        with open(path) as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None, None
    return manifest.get("total_files"), manifest.get("total_size")


def format_size(size: int) -> str:
    """Human-readable pack size."""
    if size >= 1024**3:
        return f"{size / 1024**3:.1f} GB"
    return f"{size / 1024**2:.0f} MB"


SITE_URL = "https://abdess.github.io/retrobios/"
RELEASE_URL = "../../releases/latest"
REPO = "Abdess/retrobios"


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
    """Bullet line for files matched to dump-preservation catalogs.

    Counted against the system files alone: those catalogs index console and
    computer dumps, so arcade ROM sets and engine data sit outside their
    scope and would only dilute the ratio.
    """
    sources: set[str] = set()
    matched = 0
    for entry in db.get("files", {}).values():
        provenance = entry.get("provenance")
        if not provenance:
            continue
        sources.update(provenance)
        parts = entry.get("path", "").split("/")
        top = parts[1] if len(parts) > 1 else ""
        if top != "Arcade" and top not in GAME_DATA_TOPS:
            matched += 1
    if not matched:
        return []
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

    system_ids: set[str] = set()
    for p in profiles.values():
        system_ids.update(p.get("systems", []))

    lines = [
        '<p align="center">',
        '  <img src=".github/assets/banner.png" alt="RetroBIOS" width="400">',
        "</p>",
        "",
        '<p align="center">',
        '  <a href="https://github.com/Abdess/retrobios/actions/workflows/build.yml">'
        '<img src="https://github.com/Abdess/retrobios/actions/workflows/build.yml/badge.svg" alt="Build"></a>',
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
        "# Handheld (SD card mounted on PC)",
        "curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh -s -- --platform retroarch --dest /path/to/sdcard",
        "```",
        "",
        "The script auto-detects your platform, downloads only missing files, and verifies checksums.",
        "",
        "## Download BIOS packs",
        "",
        "Pick your platform, download the ZIP, extract to the BIOS path.",
        "",
        "| Platform | Size | Extract to | Download |",
        "|----------|------|-----------|----------|",
    ]

    # Where the pack itself is extracted, which is not always the BIOS folder:
    # a pack whose entries already carry their own root (RetroDECK) extracts
    # one level above it.
    extract_paths = {
        "RetroArch": "`system/`",
        "Lakka": "`/storage/system/`",
        "Batocera": "`/userdata/bios/`",
        "BizHawk": "`Firmware/`",
        "Recalbox": "`/recalbox/share/bios/`",
        "RetroBat": "`bios/`",
        "RetroPie": "`~/RetroPie/BIOS/`",
        "RetroDECK": "`~/retrodeck/`",
        "EmuDeck": "`~/Emulation/bios/`",
        "RomM": "`bios/{platform_slug}/`",
        "ROCKNIX": "`/storage/roms/bios/`",
        "MiSTer FPGA": "`/media/fat/games/`",
    }
    archived = {
        name
        for name, entry in load_platform_registry(platforms_dir).items()
        if entry.get("status") == "archived"
    }

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        if name in archived:
            display = f"{display} *"
        path = extract_paths.get(cov["platform"], "")
        _, size = manifest_totals(name)
        size_cell = format_size(size) if size else "-"
        lines.append(
            f"| {display} | {size_cell} | {path} | [Download]({RELEASE_URL}) |"
        )

    if archived:
        lines.extend(
            [
                "",
                "The RetroDECK pack already contains its own `bios/` folder, so it"
                " extracts into `~/retrodeck/` rather than into the BIOS folder.",
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
            "Every file passes the check its platform runs at startup: an MD5 or"
            " SHA1 comparison on most, file presence on RetroArch, Lakka and"
            " RetroPie, whose code checks nothing else. That is what the"
            " Verified by column reports, platform by platform. The collection"
            " itself carries SHA1, MD5, SHA256 and CRC32 for every file, and"
            " where an emulator profile exists the expected hashes and sizes"
            " come from that emulator's own source.",
            "",
            (
                f"- **{missing_total} files** the platforms' emulators load are"
                f" not in the collection yet, named in the"
                f" [gap analysis]({SITE_URL}gaps/)"
                if missing_total
                else "- **Nothing missing**: every file the platforms'"
                " emulators load is in the collection"
            ),
            f"- **{len(coverages)} platforms** supported with platform-specific verification",
            f"- **{emulator_count} emulators** profiled from source (RetroArch cores + standalone)",
            f"- **{len(system_ids)} systems** covered (NES, SNES, PlayStation, Saturn, Dreamcast, ...)",
            f"- **{total_files:,} files** indexed with SHA1, MD5, SHA256 and CRC32 checksums:"
            f" {comp['systems']['files']:,} system files,"
            f" {comp['arcade']['files']:,} arcade ROM sets,"
            f" {comp['game_data']['files']:,} game and engine data files",
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
            "| Platform | Platform list | Read from emulator code | Verified by |",
            "|----------|--------------:|------------------------:|-------------|",
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
            "Each fraction reads collected over needed, required and optional"
            " files alike, since both go in the pack. Platform list is the BIOS"
            " list the platform publishes. Read from emulator code counts the"
            " files the cores it ships load that the list never mentions,"
            " traced in their source: routinely several times the list itself,"
            " and it includes the files documented as impossible to source.",
            "It is a floor, not a ceiling: a core that accepts any file handed"
            " to it declares nothing to count, so what such an emulator can"
            " load is not enumerable from its code.",
            f"The [gap analysis]({SITE_URL}gaps/) page names those missing files"
            " and details how far each platform's files are corroborated against"
            " emulator source code.",
            "",
            "## Build your own pack",
            "",
            "Clone the repo and generate packs for any platform, emulator, or system:",
            "",
            "```bash",
            "# Full platform pack",
            "python scripts/generate_pack.py --platform retroarch --output-dir dist/",
            "python scripts/generate_pack.py --platform batocera --output-dir dist/",
            "",
            "# Single emulator or system",
            "python scripts/generate_pack.py --emulator dolphin",
            "python scripts/generate_pack.py --system sony-playstation-2",
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
                f'<a href="{url}"><img src="{avatar}" width="50" title="{login}"></a>'
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
            " backup, archival, and interoperability with emulation software.",
            f"The legal reasoning is laid out in the [FAQ]({SITE_URL}wiki/faq/#is-this-legal).",
            "",
            f"*Auto-generated on {ts}*",
        ]
    )

    return "\n".join(lines) + "\n"


def generate_contributing() -> str:
    return f"""# Contributing to RetroBIOS

## Add a BIOS file

1. Fork this repository
2. Place the file in `bios/Manufacturer/Console/filename`
3. Variants (alternate hashes for the same file): `bios/Manufacturer/Console/.variants/`
4. Open a Pull Request - hashes are verified automatically and reported as a comment

The [dump provenance]({SITE_URL}provenance/) page lists catalogued dumps still
missing from the collection, with their hashes. A file matching one of those is
the most useful contribution.

## Add a platform

1. Write a scraper in `scripts/scraper/` (inherit `BaseScraper`)
2. Read the platform's upstream source to determine how it checks BIOS files
3. Register it in `platforms/_registry.yml`
4. Generate the platform YAML and test: `python scripts/verify.py --platform <name>`

Full walkthrough: [adding a platform]({SITE_URL}wiki/adding-a-platform/).

## Add an emulator profile

1. Clone the emulator's source code, upstream and libretro port
2. Trace the file loading from the entry point, not from a keyword grep
3. Document every file the code loads, with a `source_ref` line reference
4. Write the YAML to `emulators/<name>.yml`
5. Test: `python scripts/cross_reference.py --emulator <name>`

Full walkthrough: [profiling guide]({SITE_URL}wiki/profiling/).

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
on the documentation site, and in the BIOS packs.
"""


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
