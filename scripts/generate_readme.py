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
from common import load_database, load_platform_config
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

    platform_names = sorted(
        p.stem for p in Path(platforms_dir).glob("*.yml")
        if not p.name.startswith("_")
    )

    coverages = {}
    for name in platform_names:
        try:
            coverages[name] = compute_coverage(name, platforms_dir, db)
        except FileNotFoundError:
            pass

    emulator_count = sum(
        1 for f in Path("emulators").glob("*.yml")
    ) if Path("emulators").exists() else 0

    lines = [
        "# RetroBIOS",
        "",
        "Source-verified BIOS and firmware packs for retrogaming platforms.",
        "",
        "Every file in this collection is traced to its ground truth: the emulator's source code.",
        "Not .info files, not documentation, not community wikis - the actual code that loads the file.",
        f"{emulator_count} emulators profiled from source, {len(coverages)} platforms cross-referenced,",
        f"{total_files:,} files verified.",
        "",
        "### How it works",
        "",
        "1. **Profile emulators from source code** - read the code, document every file loaded, its hash, size, and validation",
        "2. **Cross-reference with platforms** - each platform (RetroArch, Batocera, Recalbox...) declares what it needs",
        "3. **Build packs** - for each platform, include the baseline files + what its cores actually require",
        "4. **Verify everything** - platform-native verification (MD5, existence) + emulator-level validation (CRC32, SHA256, size)",
        "",
        "When a platform and an emulator disagree on a file, we detect it. When a better variant exists in the repo, we use it.",
        "",
        f"> **{total_files:,}** files | **{size_mb:.1f} MB** | **{len(coverages)}** platforms | **{emulator_count}** emulator profiles",
        "",
        "## Download",
        "",
        "| Platform | Files | Verification | Pack |",
        "|----------|-------|-------------|------|",
    ]

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        lines.append(
            f"| {cov['platform']} | {cov['total']} | {cov['mode']} | "
            f"[Download]({RELEASE_URL}) |"
        )

    lines.extend([
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
        "## Documentation",
        "",
        f"Full file listings, platform coverage, emulator profiles, and gap analysis: **[{SITE_URL}]({SITE_URL})**",
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
