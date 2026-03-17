#!/usr/bin/env python3
"""Generate README.md and CONTRIBUTING.md from database.json and platform configs.

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
from common import load_platform_config

try:
    import yaml
except ImportError:
    print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)


def load_database(db_path: str) -> dict:
    with open(db_path) as f:
        return json.load(f)


def load_platform_configs(platforms_dir: str) -> dict:
    """Load all platform configs with inheritance resolved."""
    configs = {}
    for f in sorted(Path(platforms_dir).glob("*.yml")):
        if f.name.startswith("_"):
            continue
        try:
            config = load_platform_config(f.stem, platforms_dir)
            if config:
                configs[f.stem] = config
        except Exception as e:
            print(f"Warning: {f.name}: {e}", file=sys.stderr)
    return configs


def compute_coverage(config: dict, db: dict, **kwargs) -> dict:
    """Compute BIOS coverage by delegating to verify.py's platform-aware logic."""
    sys.path.insert(0, os.path.dirname(__file__))
    from verify import verify_platform

    result = verify_platform(config, db)

    present = result["ok"] + result["untested"]
    pct = (present / result["total"] * 100) if result["total"] > 0 else 0

    return {
        "total": result["total"],
        "verified": result["ok"],
        "untested": result["untested"],
        "present": present,
        "missing": [d["name"] for d in result["details"] if d["status"] == "missing"],
        "percentage": pct,
        "verification_mode": result["verification_mode"],
    }


def status_badge(pct: float, platform: str = "") -> str:
    """Generate a shields.io badge URL for platform coverage."""
    if pct >= 90:
        color = "brightgreen"
    elif pct >= 70:
        color = "yellow"
    else:
        color = "red"
    label = platform.replace(" ", "%20") if platform else "coverage"
    return f"![{platform} {pct:.0f}%](https://img.shields.io/badge/{label}-{pct:.0f}%25-{color})"


def status_emoji(pct: float) -> str:
    if pct >= 90:
        return "🟢"
    elif pct >= 70:
        return "🟡"
    else:
        return "🔴"


def _rel_link(path: str) -> str:
    """Build a relative link to a file in the repo."""
    encoded = path.replace(" ", "%20").replace("(", "%28").replace(")", "%29")
    return encoded


def generate_readme(db: dict, configs: dict) -> str:
    """Generate README.md content."""
    generated_at = db.get("generated_at", "unknown")
    total_files = db.get("total_files", 0)
    total_size_mb = db.get("total_size", 0) / (1024 * 1024)

    systems = {}
    for sha1, entry in db.get("files", {}).items():
        path = entry.get("path", "")
        parts = path.split("/")
        if len(parts) >= 3:
            system = f"{parts[1]}/{parts[2]}"
        elif len(parts) >= 2:
            system = parts[1]
        else:
            system = "Other"
        systems.setdefault(system, []).append(entry)

    lines = []
    lines.append("# Retrogaming BIOS & Firmware Collection")
    lines.append("")
    lines.append("Complete, verified collection of BIOS, firmware, and system files "
                 "for retrogaming emulators - RetroArch, Batocera, Recalbox, Lakka, "
                 "RetroPie, and more. Every file checked against official checksums "
                 "from [libretro System.dat](https://github.com/libretro/libretro-database), "
                 "[batocera-systems](https://github.com/batocera-linux/batocera.linux), "
                 "and [Recalbox es_bios.xml](https://gitlab.com/recalbox/recalbox).")
    lines.append("")
    lines.append(f"> **{total_files}** files | **{total_size_mb:.1f} MB** | "
                 f"Last updated: {generated_at}")
    lines.append(">")
    lines.append("> PlayStation, PS2, Nintendo DS, Game Boy, GBA, Dreamcast, Saturn, "
                 "Neo Geo, Mega CD, PC Engine, MSX, Amiga, Atari ST, ZX Spectrum, "
                 "Arcade (MAME/FBNeo), and 50+ systems.")
    lines.append("")
    lines.append("## Quick Start")
    lines.append("")
    lines.append("### Download a complete pack")
    lines.append("")
    lines.append("Go to [Releases](../../releases) and download the ZIP for your platform.")
    lines.append("")
    lines.append("### Using the download tool")
    lines.append("")
    lines.append("```bash")
    lines.append("# List available platforms")
    lines.append("python scripts/download.py --list")
    lines.append("")
    lines.append("# Download BIOS pack for RetroArch")
    lines.append("python scripts/download.py retroarch ~/RetroArch/system/")
    lines.append("")
    lines.append("# Verify existing BIOS files")
    lines.append("python scripts/download.py --verify retroarch ~/RetroArch/system/")
    lines.append("```")
    lines.append("")
    lines.append("### Generate a pack locally (any platform)")
    lines.append("")
    lines.append("Some platforms are archived and not included in automated releases. "
                 "You can generate any pack locally - including archived ones:")
    lines.append("")
    lines.append("```bash")
    lines.append("git clone https://github.com/Abdess/retroarch_system.git")
    lines.append("cd retroarch_system")
    lines.append("pip install pyyaml")
    lines.append("")
    lines.append("# Generate for a specific platform")
    lines.append("python scripts/generate_pack.py --platform retropie --output-dir ~/Downloads/")
    lines.append("")
    lines.append("# Generate for ALL platforms (including archived)")
    lines.append("python scripts/generate_pack.py --all --include-archived --output-dir ~/Downloads/")
    lines.append("```")
    lines.append("")

    registry = {}
    registry_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "platforms", "_registry.yml")
    if os.path.exists(registry_path):
        with open(registry_path) as f:
            registry = (yaml.safe_load(f) or {}).get("platforms", {})

    if configs:
        lines.append("## Platform Coverage")
        lines.append("")
        lines.append("| Platform | Coverage | Status | Verification | Details |")
        lines.append("|----------|----------|--------|--------------|---------|")

        for name, config in sorted(configs.items()):
            platform_display = config.get("platform", name)
            platform_status = registry.get(name, {}).get("status", "active")
            coverage = compute_coverage(config, db)
            badge = status_badge(coverage["percentage"], platform_display)
            emoji = status_emoji(coverage["percentage"])
            mode = coverage["verification_mode"]

            if platform_status == "archived":
                badge = f"![{platform_display}](https://img.shields.io/badge/{platform_display.replace(' ', '%20')}-archived-lightgrey)"
                emoji = "📦"

            if mode == "existence":
                detail = f"{coverage['verified']} present"
                if coverage['missing']:
                    detail += f", {len(coverage['missing'])} missing"
            else:
                parts = []
                if coverage['verified']:
                    parts.append(f"{coverage['verified']} verified")
                if coverage['untested']:
                    parts.append(f"{coverage['untested']} untested")
                if coverage['missing']:
                    parts.append(f"{len(coverage['missing'])} missing")
                detail = ", ".join(parts) if parts else "0 files"

            if platform_status == "archived":
                detail += " *(archived - generate manually)*"

            lines.append(
                f"| {platform_display} | "
                f"{coverage['present']}/{coverage['total']} ({coverage['percentage']:.1f}%) | "
                f"{badge} {emoji} | "
                f"{mode} | "
                f"{detail} |"
            )

        lines.append("")

    DATA_PACK_MARKERS = {"RPG Maker", "ScummVM"}

    bios_systems = {}
    data_packs = {}
    for system_name, files in systems.items():
        if any(marker in system_name for marker in DATA_PACK_MARKERS):
            data_packs[system_name] = files
        else:
            bios_systems[system_name] = files

    lines.append("## Systems")
    lines.append("")
    lines.append("| System | Files | Size |")
    lines.append("|--------|-------|------|")

    for system_name, files in sorted(bios_systems.items()):
        total_size = sum(f.get("size", 0) for f in files)
        if total_size > 1024 * 1024:
            size_str = f"{total_size / (1024*1024):.1f} MB"
        elif total_size > 1024:
            size_str = f"{total_size / 1024:.1f} KB"
        else:
            size_str = f"{total_size} B"
        lines.append(f"| {system_name} | {len(files)} | {size_str} |")

    lines.append("")

    if data_packs:
        lines.append("## Data Packs")
        lines.append("")
        lines.append("These are large asset packs required by specific cores. "
                     "They are included in the repository but not listed individually.")
        lines.append("")
        lines.append("| Pack | Files | Size |")
        lines.append("|------|-------|------|")
        for pack_name, files in sorted(data_packs.items()):
            total_size = sum(f.get("size", 0) for f in files)
            size_str = f"{total_size / (1024*1024):.1f} MB" if total_size > 1024*1024 else f"{total_size / 1024:.1f} KB"
            # Link to the manufacturer/system directory
            first_path = files[0].get("path", "") if files else ""
            parts = first_path.split("/")
            pack_path = "/".join(parts[:3]) if len(parts) >= 3 else first_path
            lines.append(f"| [{pack_name}]({_rel_link(pack_path)}) | {len(files)} | {size_str} |")
        lines.append("")

    platform_names = {}
    by_name_idx = db.get("indexes", {}).get("by_name", {})
    files_db = db.get("files", {})
    for cfg_name, cfg in configs.items():
        plat_display = cfg.get("platform", cfg_name)
        for sys_id, system in cfg.get("systems", {}).items():
            for fe in system.get("files", []):
                fe_name = fe.get("name", "")
                fe_dest = fe.get("destination", fe_name)
                fe_sha1 = fe.get("sha1")
                fe_md5 = fe.get("md5", "").split(",")[0].strip() if fe.get("md5") else ""
                # Find matching SHA1
                matched_sha1 = None
                if fe_sha1 and fe_sha1 in files_db:
                    matched_sha1 = fe_sha1
                elif fe_md5:
                    matched_sha1 = db.get("indexes", {}).get("by_md5", {}).get(fe_md5.lower())
                    if not matched_sha1:
                        matched_sha1 = db.get("indexes", {}).get("by_md5", {}).get(fe_md5)
                if not matched_sha1 and fe_name in by_name_idx:
                    matched_sha1 = by_name_idx[fe_name][0]
                if matched_sha1:
                    if matched_sha1 not in platform_names:
                        platform_names[matched_sha1] = []
                    dest_name = fe_dest.split("/")[-1] if "/" in fe_dest else fe_dest
                    if dest_name != files_db.get(matched_sha1, {}).get("name", ""):
                        entry = (plat_display, dest_name)
                        if entry not in platform_names[matched_sha1]:
                            platform_names[matched_sha1].append(entry)

    variants_map = {}
    for sha1, entry in files_db.items():
        if ".variants/" not in entry.get("path", ""):
            continue
        vname = entry["name"]
        # Strip the .sha1short suffix to get the original filename
        parts = vname.rsplit(".", 1)
        if len(parts) == 2 and len(parts[1]) == 8 and all(c in "0123456789abcdef" for c in parts[1]):
            base_name = parts[0]
        else:
            base_name = vname
        variants_map.setdefault(base_name, []).append(entry)

    lines.append("## BIOS File Listing")
    lines.append("")

    for system_name, files in sorted(bios_systems.items()):
        lines.append(f"### {system_name}")
        lines.append("")

        for entry in sorted(files, key=lambda x: x["name"]):
            name = entry["name"]
            path = entry.get("path", "")
            size = entry.get("size", 0)
            sha1 = entry.get("sha1", "")
            dl_link = _rel_link(path)
            lines.append(f"- **[{name}]({dl_link})** ({size:,} bytes)")
            lines.append(f"  - SHA1: `{sha1 or 'N/A'}`")
            lines.append(f"  - MD5: `{entry.get('md5', 'N/A')}`")
            lines.append(f"  - CRC32: `{entry.get('crc32', 'N/A')}`")

            if sha1:
                alt_names = []
                for alias_name, alias_sha1s in by_name_idx.items():
                    if sha1 in alias_sha1s and alias_name != name:
                        alt_names.append(alias_name)
                if alt_names:
                    lines.append(f"  - Also known as: {', '.join(f'`{a}`' for a in sorted(alt_names))}")

            if sha1 and sha1 in platform_names and platform_names[sha1]:
                plat_refs = [f"{plat}: `{dest}`" for plat, dest in platform_names[sha1]]
                lines.append(f"  - Platform names: {', '.join(plat_refs)}")

            if name in variants_map:
                vlist = variants_map[name]
                lines.append(f"  - **Variants** ({len(vlist)} alternate versions):")
                for v in sorted(vlist, key=lambda x: x["name"]):
                    vlink = _rel_link(v["path"])
                    lines.append(f"    - [{v['name']}]({vlink}) ({v['size']:,} bytes) "
                                 f"- SHA1: `{v['sha1']}`, MD5: `{v['md5']}`")

        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Contributing")
    lines.append("")
    lines.append("See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting BIOS files.")
    lines.append("")
    lines.append("## License")
    lines.append("")
    lines.append("This repository provides BIOS files for personal backup and archival purposes.")
    lines.append("")
    lines.append(f"*Auto-generated on {generated_at}*")
    lines.append("")

    return "\n".join(lines)


def generate_contributing() -> str:
    """Generate CONTRIBUTING.md content."""
    return """# Contributing BIOS Files

Thank you for helping expand the BIOS collection!

## How to Contribute

1. **Fork** this repository
2. **Add** your BIOS file to the correct directory under `bios/Manufacturer/Console/`
3. **Create a Pull Request**

## File Placement

Place files in the correct manufacturer/console directory:
```
bios/
├── Sony/
│   └── PlayStation/
│       └── scph5501.bin
├── Nintendo/
│   └── Game Boy Advance/
│       └── gba_bios.bin
└── Sega/
    └── Dreamcast/
        └── dc_boot.bin
```

## Verification

All submitted BIOS files are automatically verified against known checksums:

1. **Hash verification** - SHA1/MD5 checked against known databases
2. **Size verification** - File size matches expected value
3. **Platform reference** - File must be referenced in at least one platform config
4. **Duplicate detection** - Existing files are flagged to avoid duplication

## What We Accept

- **Verified BIOS dumps** with matching checksums from known databases
- **System firmware** required by emulators
- **New variants** of existing BIOS files (different regions, versions)

## What We Don't Accept

- Game ROMs or ISOs
- Modified/patched BIOS files
- Files without verifiable checksums
- Executable files (.exe, .bat, .sh)

## Questions?

Open an [Issue](../../issues) if you're unsure about a file.
"""


def main():
    parser = argparse.ArgumentParser(description="Generate README.md and CONTRIBUTING.md")
    parser.add_argument("--db", default="database.json", help="Path to database.json")
    parser.add_argument("--platforms-dir", default="platforms", help="Platforms config directory")
    parser.add_argument("--output-dir", default=".", help="Output directory for README/CONTRIBUTING")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"Error: {args.db} not found. Run generate_db.py first.", file=sys.stderr)
        sys.exit(1)

    db = load_database(args.db)
    configs = load_platform_configs(args.platforms_dir) if os.path.isdir(args.platforms_dir) else {}

    readme = generate_readme(db, configs)
    readme_path = os.path.join(args.output_dir, "README.md")
    with open(readme_path, "w") as f:
        f.write(readme)
    print(f"Generated {readme_path}")

    contributing = generate_contributing()
    contributing_path = os.path.join(args.output_dir, "CONTRIBUTING.md")
    with open(contributing_path, "w") as f:
        f.write(contributing)
    print(f"Generated {contributing_path}")


if __name__ == "__main__":
    main()
