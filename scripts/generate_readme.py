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
from common import list_registered_platforms, load_database, load_platform_config
from verify import verify_platform

def compute_coverage(platform_name: str, platforms_dir: str, db: dict) -> dict:
    config = load_platform_config(platform_name, platforms_dir)
    result = verify_platform(config, db)
    sc = result.get("status_counts", {})
    ok = sc.get("ok", 0)
    untested = sc.get("untested", 0)
    missing = sc.get("missing", 0)
    total = result["total_files"]
    present = ok + untested
    pct = (present / total * 100) if total > 0 else 0
    return {
        "platform": config.get("platform", platform_name),
        "total": total,
        "verified": ok,
        "untested": untested,
        "missing": missing,
        "present": present,
        "percentage": pct,
        "mode": config.get("verification_mode", "existence"),
        "details": result["details"],
        "config": config,
    }


SITE_URL = "https://abdess.github.io/retrobios/"
RELEASE_URL = "../../releases/latest"
REPO = "Abdess/retrobios"


def fetch_contributors() -> list[dict]:
    """Fetch contributors from GitHub API, exclude bots."""
    import urllib.request
    import urllib.error
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
            c for c in data
            if not c.get("login", "").endswith("[bot]")
            and c.get("type") == "User"
            and c.get("login") != owner
        ]
    except (urllib.error.URLError, urllib.error.HTTPError):
        return []


def generate_readme(db: dict, platforms_dir: str) -> str:
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    size_mb = total_size / (1024 * 1024)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    platform_names = list_registered_platforms(platforms_dir, include_archived=True)

    coverages = {}
    for name in platform_names:
        try:
            coverages[name] = compute_coverage(name, platforms_dir, db)
        except FileNotFoundError:
            pass

    emulator_count = sum(
        1 for f in Path("emulators").glob("*.yml")
    ) if Path("emulators").exists() else 0

    # Count systems from emulator profiles
    system_ids: set[str] = set()
    emu_dir = Path("emulators")
    if emu_dir.exists():
        try:
            import yaml
            for f in emu_dir.glob("*.yml"):
                with open(f) as fh:
                    p = yaml.safe_load(fh) or {}
                system_ids.update(p.get("systems", []))
        except ImportError:
            pass

    lines = [
        "# RetroBIOS",
        "",
        f"Complete BIOS and firmware packs for "
        f"{', '.join(c['platform'] for c in sorted(coverages.values(), key=lambda x: x['platform'])[:-1])}"
        f", and {sorted(coverages.values(), key=lambda x: x['platform'])[-1]['platform']}.",
        "",
        f"**{total_files:,}** verified files across **{len(system_ids)}** systems,"
        f" ready to extract into your emulator's BIOS directory.",
        "",
        "## Download BIOS packs",
        "",
        "Pick your platform, download the ZIP, extract to the BIOS path.",
        "",
        "| Platform | BIOS files | Extract to | Download |",
        "|----------|-----------|-----------|----------|",
    ]

    extract_paths = {
        "RetroArch": "`system/`",
        "Lakka": "`system/`",
        "Batocera": "`/userdata/bios/`",
        "Recalbox": "`/recalbox/share/bios/`",
        "RetroBat": "`bios/`",
        "RetroPie": "`BIOS/`",
        "RetroDECK": "`~/retrodeck/bios/`",
        "EmuDeck": "`Emulation/bios/`",
        "RomM": "`bios/{platform_slug}/`",
    }

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        path = extract_paths.get(display, "")
        lines.append(
            f"| {display} | {cov['total']} | {path} | "
            f"[Download]({RELEASE_URL}) |"
        )

    lines.extend([
        "",
        "## What's included",
        "",
        "BIOS, firmware, and system files for consoles from Atari to PlayStation 3.",
        f"Each file is checked against the emulator's source code to match what the"
        f" code actually loads at runtime.",
        "",
        f"- **{len(coverages)} platforms** supported with platform-specific verification",
        f"- **{emulator_count} emulators** profiled from source (RetroArch cores + standalone)",
        f"- **{len(system_ids)} systems** covered (NES, SNES, PlayStation, Saturn, Dreamcast, ...)",
        f"- **{total_files:,} files** verified with MD5, SHA1, CRC32 checksums",
        f"- **{size_mb:.0f} MB** total collection size",
        "",
        "## Supported systems",
        "",
    ])

    # Show well-known systems for SEO, link to full list
    well_known = [
        "NES", "SNES", "Nintendo 64", "GameCube", "Wii", "Game Boy", "Game Boy Advance",
        "Nintendo DS", "Nintendo 3DS", "Switch",
        "PlayStation", "PlayStation 2", "PlayStation 3", "PSP", "PS Vita",
        "Mega Drive", "Saturn", "Dreamcast", "Game Gear", "Master System",
        "Neo Geo", "Atari 2600", "Atari 7800", "Atari Lynx", "Atari ST",
        "MSX", "PC Engine", "TurboGrafx-16", "ColecoVision", "Intellivision",
        "Commodore 64", "Amiga", "ZX Spectrum", "Arcade (MAME)",
    ]
    lines.extend([
        ", ".join(well_known) + f", and {len(system_ids) - len(well_known)}+ more.",
        "",
        f"Full list with per-file details: **[{SITE_URL}]({SITE_URL})**",
        "",
        "## Coverage",
        "",
        "| Platform | Coverage | Verified | Untested | Missing |",
        "|----------|----------|----------|----------|---------|",
    ])

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        pct = f"{cov['percentage']:.1f}%"
        lines.append(
            f"| {cov['platform']} | {cov['present']}/{cov['total']} ({pct}) | "
            f"{cov['verified']} | {cov['untested']} | {cov['missing']} |"
        )

    lines.extend([
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
        "```",
        "",
        f"Only dependency: Python 3 + `pyyaml`.",
        "",
        "## Documentation site",
        "",
        f"The [documentation site]({SITE_URL}) provides:",
        "",
        f"- **Per-platform pages** with file-by-file verification status and hashes",
        f"- **Per-emulator profiles** with source code references for every file",
        f"- **Per-system pages** showing which emulators and platforms cover each console",
        f"- **Gap analysis** identifying missing files and undeclared core requirements",
        f"- **Cross-reference** mapping files across {len(coverages)} platforms and {emulator_count} emulators",
        "",
        "## How it works",
        "",
        "Documentation and metadata can drift from what emulators actually load.",
        "To keep packs accurate, each file is checked against the emulator's source code.",
        "",
        "1. **Read emulator source code** - trace every file the code loads, its expected hash and size",
        "2. **Cross-reference with platforms** - match against what each platform declares",
        "3. **Build packs** - include baseline files plus what each platform's cores need",
        "4. **Verify** - run platform-native checks and emulator-level validation",
        "",
    ])

    contributors = fetch_contributors()
    if contributors:
        lines.extend([
            "## Contributors",
            "",
        ])
        for c in contributors:
            login = c["login"]
            avatar = c.get("avatar_url", "")
            url = c.get("html_url", f"https://github.com/{login}")
            lines.append(
                f'<a href="{url}"><img src="{avatar}" width="50" title="{login}"></a>'
            )
        lines.append("")

    lines.extend([
        "",
        "## Contributing",
        "",
        "See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.",
        "",
        "## License",
        "",
        "This repository provides BIOS files for personal backup and archival purposes.",
        "",
        f"*Auto-generated on {ts}*",
    ])

    return "\n".join(lines) + "\n"


def generate_contributing() -> str:
    return """# Contributing to RetroBIOS

## Add a BIOS file

1. Fork this repository
2. Place the file in `bios/Manufacturer/Console/filename`
3. Variants (alternate hashes): `bios/Manufacturer/Console/.variants/`
4. Create a Pull Request - checksums are verified automatically

## File conventions

- Files >50 MB go in GitHub release assets (`large-files` release)
- RPG Maker and ScummVM directories are excluded from deduplication
- See the [documentation site](https://abdess.github.io/retrobios/) for full details
"""


def main():
    parser = argparse.ArgumentParser(description="Generate slim README.md")
    parser.add_argument("--db", default="database.json")
    parser.add_argument("--platforms-dir", default="platforms")
    args = parser.parse_args()

    db = load_database(args.db)

    readme = generate_readme(db, args.platforms_dir)
    with open("README.md", "w") as f:
        f.write(readme)
    print(f"Generated ./README.md")

    contributing = generate_contributing()
    with open("CONTRIBUTING.md", "w") as f:
        f.write(contributing)
    print(f"Generated ./CONTRIBUTING.md")


if __name__ == "__main__":
    main()
