#!/usr/bin/env python3
"""Generate MkDocs site pages from database.json, platform configs, and emulator profiles.

Reads the same data sources as verify.py and generate_pack.py to produce
a complete documentation site. Zero manual content.

Usage:
    python scripts/generate_site.py
    python scripts/generate_site.py --db database.json --platforms-dir platforms
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, os.path.dirname(__file__))
from common import load_database, load_platform_config, compute_coverage

DOCS_DIR = "docs"
SITE_NAME = "RetroBIOS"
REPO_URL = "https://github.com/Abdess/retrobios"
RELEASE_URL = f"{REPO_URL}/releases/latest"
GENERATED_DIRS = ["platforms", "systems", "emulators"]


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_size(size: int) -> str:
    if size >= 1024 * 1024 * 1024:
        return f"{size / (1024**3):.1f} GB"
    if size >= 1024 * 1024:
        return f"{size / (1024**2):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n / total * 100:.1f}%"


def _status_icon(pct: float) -> str:
    if pct >= 100:
        return "OK"
    if pct >= 95:
        return "~OK"
    return "partial"


# ---------------------------------------------------------------------------
# Coverage computation (reuses verify.py logic)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Load emulator profiles
# ---------------------------------------------------------------------------

def _load_emulator_profiles(emulators_dir: str) -> dict[str, dict]:
    profiles = {}
    emu_path = Path(emulators_dir)
    if not emu_path.exists():
        return profiles
    for f in sorted(emu_path.glob("*.yml")):
        with open(f) as fh:
            profile = yaml.safe_load(fh) or {}
        profiles[f.stem] = profile
    return profiles


# ---------------------------------------------------------------------------
# Home page
# ---------------------------------------------------------------------------

def generate_home(db: dict, coverages: dict, emulator_count: int,
                   registry: dict | None = None) -> str:
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    ts = _timestamp()

    lines = [
        f"# {SITE_NAME}",
        "",
        "Complete BIOS and firmware collection for retrogaming emulators.",
        "",
        "---",
        "",
        f"**{total_files:,}** files across **{len(coverages)}** platforms, "
        f"backed by **{emulator_count}** emulator source code profiles.",
        "",
    ]

    # Single unified table: platform + coverage + download
    lines.extend([
        "## Platforms",
        "",
        "| | Platform | Coverage | Verified | Download |",
        "|---|----------|----------|----------|----------|",
    ])

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        pct = _pct(cov["present"], cov["total"])
        logo_url = (registry or {}).get(name, {}).get("logo", "")
        logo_md = f"![{display}]({logo_url}){{ width=20 loading=lazy }}" if logo_url else ""

        lines.append(
            f"| {logo_md} | [{display}](platforms/{name}.md) | "
            f"{cov['present']}/{cov['total']} ({pct}) | "
            f"{cov['verified']} | "
            f"[Pack]({RELEASE_URL}) |"
        )

    # Quick links
    lines.extend([
        "",
        "---",
        "",
        f"[Systems](systems/){{ .md-button }} "
        f"[Emulators](emulators/){{ .md-button }} "
        f"[Gap Analysis](gaps/){{ .md-button }} "
        f"[Contributing](contributing/){{ .md-button .md-button--primary }}",
        "",
        f"*{_fmt_size(total_size)} total. Generated on {ts}.*",
    ])

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Platform pages
# ---------------------------------------------------------------------------

def generate_platform_index(coverages: dict) -> str:
    lines = [
        f"# Platforms - {SITE_NAME}",
        "",
        "| Platform | Coverage | Verification | Status |",
        "|----------|----------|-------------|--------|",
    ]

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        pct = _pct(cov["present"], cov["total"])
        plat_status = cov["config"].get("status", "active")
        status = "archived" if plat_status == "archived" else _status_icon(cov["percentage"])
        lines.append(
            f"| [{display}]({name}.md) | "
            f"{cov['present']}/{cov['total']} ({pct}) | "
            f"{cov['mode']} | {status} |"
        )

    return "\n".join(lines) + "\n"


def generate_platform_page(name: str, cov: dict, registry: dict | None = None) -> str:
    config = cov["config"]
    display = cov["platform"]
    mode = cov["mode"]
    pct = _pct(cov["present"], cov["total"])

    logo_url = (registry or {}).get(name, {}).get("logo", "")
    logo_md = f"![{display}]({logo_url}){{ width=48 align=right }}\n\n" if logo_url else ""

    lines = [
        f"# {display} - {SITE_NAME}",
        "",
        logo_md + f"**Verification mode:** {mode}",
        f"**Coverage:** {cov['present']}/{cov['total']} ({pct})",
        f"**Verified:** {cov['verified']} | **Untested:** {cov['untested']} | **Missing:** {cov['missing']}",
        "",
        f"[Download {display} Pack]({RELEASE_URL}){{ .md-button }}",
        "",
    ]

    # Group details by system
    by_system: dict[str, list] = {}
    for d in cov["details"]:
        sys_id = d.get("system", "unknown")
        by_system.setdefault(sys_id, []).append(d)

    for sys_id, files in sorted(by_system.items()):
        ok_count = sum(1 for f in files if f["status"] == "ok")
        total = len(files)
        lines.append(f"## {sys_id}")
        lines.append(f"")
        lines.append(f"{ok_count}/{total} verified")
        lines.append("")

        # Only show table if there are non-OK entries, otherwise just list filenames
        non_ok = [f for f in files if f["status"] != "ok"]
        if non_ok:
            lines.append("| File | Status | Detail |")
            lines.append("|------|--------|--------|")
            for f in sorted(non_ok, key=lambda x: x["name"]):
                status = f["status"]
                detail = ""
                if status == "untested":
                    reason = f.get("reason", "")
                    expected = f.get("expected_md5", "")
                    actual = f.get("actual_md5", "")
                    detail = reason or (f"expected `{expected[:12]}...` got `{actual[:12]}...`" if expected and actual else "")
                    status_display = "Untested"
                elif status == "missing":
                    status_display = "Missing"
                    detail = f"Expected: `{f.get('expected_md5', 'unknown')}`"
                else:
                    status_display = status
                lines.append(f"| `{f['name']}` | {status_display} | {detail} |")
            lines.append("")

        ok_files = [f for f in files if f["status"] == "ok"]
        if ok_files:
            unique_names = sorted(set(f["name"] for f in ok_files))
            names = ", ".join(f"`{n}`" for n in unique_names)
            lines.append(f"Files: {names}")
            lines.append("")

    lines.append(f"*Generated on {_timestamp()}*")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# System pages
# ---------------------------------------------------------------------------

def _group_by_manufacturer(db: dict) -> dict[str, dict[str, list]]:
    """Group files by manufacturer -> console -> files."""
    manufacturers: dict[str, dict[str, list]] = {}
    for sha1, entry in db.get("files", {}).items():
        path = entry.get("path", "")
        parts = path.split("/")
        if len(parts) < 3 or parts[0] != "bios":
            continue
        manufacturer = parts[1]
        console = parts[2]
        manufacturers.setdefault(manufacturer, {}).setdefault(console, []).append(entry)
    return manufacturers


def generate_systems_index(manufacturers: dict) -> str:
    lines = [
        f"# Systems - {SITE_NAME}",
        "",
        "| Manufacturer | Consoles | Files |",
        "|-------------|----------|-------|",
    ]

    for mfr in sorted(manufacturers.keys()):
        consoles = manufacturers[mfr]
        file_count = sum(len(files) for files in consoles.values())
        slug = mfr.lower().replace(" ", "-")
        lines.append(f"| [{mfr}]({slug}.md) | {len(consoles)} | {file_count} |")

    return "\n".join(lines) + "\n"


def generate_system_page(
    manufacturer: str,
    consoles: dict[str, list],
    platform_files: dict[str, set],
    emulator_files: dict[str, set],
) -> str:
    slug = manufacturer.lower().replace(" ", "-")
    lines = [
        f"# {manufacturer} - {SITE_NAME}",
        "",
    ]

    for console_name in sorted(consoles.keys()):
        files = consoles[console_name]
        lines.append(f"## {console_name}")
        lines.append("")
        # Separate main files from variants
        main_files = [f for f in files if "/.variants/" not in f["path"]]
        variant_files = [f for f in files if "/.variants/" in f["path"]]

        for f in sorted(main_files, key=lambda x: x["name"]):
            name = f["name"]
            sha1_full = f.get("sha1", "unknown")
            md5_full = f.get("md5", "unknown")
            size = _fmt_size(f.get("size", 0))

            # Cross-reference: which platforms declare this file
            plats = sorted(p for p, names in platform_files.items() if name in names)
            # Cross-reference: which emulators load this file
            emus = sorted(e for e, names in emulator_files.items() if name in names)

            lines.append(f"**`{name}`** ({size})")
            lines.append("")
            lines.append(f"- SHA1: `{sha1_full}`")
            lines.append(f"- MD5: `{md5_full}`")
            if plats:
                lines.append(f"- Platforms: {', '.join(plats)}")
            if emus:
                lines.append(f"- Emulators: {', '.join(emus)}")
            lines.append("")

        if variant_files:
            lines.append("**Variants:**")
            lines.append("")
            for v in sorted(variant_files, key=lambda x: x["name"]):
                vname = v["name"]
                vmd5 = v.get("md5", "unknown")
                lines.append(f"- `{vname}` MD5: `{vmd5}`")

        lines.append("")

    lines.append(f"*Generated on {_timestamp()}*")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Emulator pages
# ---------------------------------------------------------------------------

def generate_emulators_index(profiles: dict) -> str:
    lines = [
        f"# Emulators - {SITE_NAME}",
        "",
        "| Engine | Type | Systems | Files |",
        "|--------|------|---------|-------|",
    ]

    unique = {k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")}
    test_cores = {k: v for k, v in profiles.items() if v.get("type") == "test"}
    aliases = {k: v for k, v in profiles.items() if v.get("type") == "alias"}

    for name in sorted(unique.keys()):
        p = unique[name]
        emu_name = p.get("emulator", name)
        emu_type = p.get("type", "unknown")
        systems = p.get("systems", [])
        files = p.get("files", [])
        sys_str = ", ".join(systems[:3])
        if len(systems) > 3:
            sys_str += f" +{len(systems)-3}"

        lines.append(
            f"| [{emu_name}]({name}.md) | {emu_type} | "
            f"{sys_str} | {len(files)} |"
        )

    if aliases:
        lines.extend(["", "## Aliases", ""])
        lines.append("| Core | Points to |")
        lines.append("|------|-----------|")
        for name in sorted(aliases.keys()):
            parent = aliases[name].get("alias_of", "unknown")
            lines.append(f"| {name} | [{parent}]({parent}.md) |")

    return "\n".join(lines) + "\n"


def generate_emulator_page(name: str, profile: dict, db: dict,
                           platform_files: dict | None = None) -> str:
    if profile.get("type") == "alias":
        parent = profile.get("alias_of", "unknown")
        return (
            f"# {name} - {SITE_NAME}\n\n"
            f"This core uses the same firmware as **{parent}**.\n\n"
            f"See [{parent}]({parent}.md) for details.\n"
        )

    emu_name = profile.get("emulator", name)
    emu_type = profile.get("type", "unknown")
    source = profile.get("source", "")
    version = profile.get("core_version", "unknown")
    display = profile.get("display_name", emu_name)
    profiled = profile.get("profiled_date", "unknown")
    systems = profile.get("systems", [])
    cores = profile.get("cores", [name])
    files = profile.get("files", [])

    logo_url = profile.get("logo", "")
    logo_md = f"![{emu_name}]({logo_url}){{ width=48 align=right }}\n\n" if logo_url else ""

    lines = [
        f"# {emu_name} - {SITE_NAME}",
        "",
        logo_md + f"| | |",
        f"|---|---|",
        f"| Type | {emu_type} |",
    ]
    if source:
        lines.append(f"| Source | [{source}]({source}) |")
    lines.append(f"| Version | {version} |")
    lines.append(f"| Profiled | {profiled} |")
    if cores:
        lines.append(f"| Cores | {', '.join(str(c) for c in cores)} |")
    if systems:
        lines.append(f"| Systems | {', '.join(str(s) for s in systems)} |")
    lines.append("")

    if not files:
        lines.append("No BIOS or firmware files required. This core is self-contained.")
        note = profile.get("note", profile.get("notes", ""))
        if note:
            lines.extend(["", str(note)])
    else:
        by_name = db.get("indexes", {}).get("by_name", {})
        in_repo_count = sum(1 for f in files if f.get("name", "") in by_name)
        missing_count = len(files) - in_repo_count
        lines.append(f"**{len(files)} files** ({in_repo_count} in repo, {missing_count} missing)")
        lines.append("")

        # Check which platforms declare each file
        show_platforms = platform_files is not None

        if show_platforms:
            lines.append("| File | Required | In Repo | Platforms | Source Ref |")
            lines.append("|------|----------|---------|-----------|-----------|")
        else:
            lines.append("| File | Required | In Repo | Source Ref |")
            lines.append("|------|----------|---------|-----------|")

        for f in files:
            fname = f.get("name", "")
            required = "yes" if f.get("required") else "no"
            in_repo = "yes" if fname in by_name else "no"
            source_ref = f.get("source_ref", "")

            if show_platforms:
                plats = [p for p, names in platform_files.items() if fname in names]
                plat_str = ", ".join(sorted(plats)) if plats else "-"
                lines.append(f"| `{fname}` | {required} | {in_repo} | {plat_str} | {source_ref} |")
            else:
                lines.append(f"| `{fname}` | {required} | {in_repo} | {source_ref} |")

    lines.extend(["", f"*Generated on {_timestamp()}*"])
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Contributing page
# ---------------------------------------------------------------------------

def generate_gap_analysis(
    profiles: dict,
    coverages: dict,
    db: dict,
) -> str:
    """Generate a global gap analysis page showing all missing/undeclared files."""
    by_name = db.get("indexes", {}).get("by_name", {})
    platform_files = _build_platform_file_index(coverages)

    lines = [
        f"# Gap Analysis - {SITE_NAME}",
        "",
        "Files that emulators load but platforms don't declare, and their availability.",
        "",
    ]

    # Global stats
    total_undeclared = 0
    total_in_repo = 0
    total_missing = 0

    # Build global set of all platform-declared filenames (once)
    all_platform_names = set()
    for pfiles in platform_files.values():
        all_platform_names.update(pfiles)

    emulator_gaps = []
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") == "alias":
            continue
        files = profile.get("files", [])
        if not files:
            continue

        undeclared = []
        for f in files:
            fname = f.get("name", "")
            if not fname or fname.startswith("<"):
                continue
            if fname not in all_platform_names:
                in_repo = fname in by_name
                undeclared.append({
                    "name": fname,
                    "required": f.get("required", False),
                    "in_repo": in_repo,
                    "source_ref": f.get("source_ref", ""),
                })
                total_undeclared += 1
                if in_repo:
                    total_in_repo += 1
                else:
                    total_missing += 1

        if undeclared:
            emulator_gaps.append((emu_name, profile.get("emulator", emu_name), undeclared))

    lines.extend([
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total undeclared files | {total_undeclared} |",
        f"| Already in repo | {total_in_repo} |",
        f"| Missing from repo | {total_missing} |",
        f"| Emulators with gaps | {len(emulator_gaps)} |",
        "",
    ])

    # Per-emulator breakdown
    lines.extend([
        "## Per Emulator",
        "",
        "| Emulator | Undeclared | In Repo | Missing |",
        "|----------|-----------|---------|---------|",
    ])

    for emu_name, display, gaps in sorted(emulator_gaps, key=lambda x: -len(x[2])):
        in_repo = sum(1 for g in gaps if g["in_repo"])
        missing = len(gaps) - in_repo
        lines.append(f"| [{display}](emulators/{emu_name}.md) | {len(gaps)} | {in_repo} | {missing} |")

    # Missing files detail (not in repo)
    all_missing = set()
    missing_details = []
    for emu_name, display, gaps in emulator_gaps:
        for g in gaps:
            if not g["in_repo"] and g["name"] not in all_missing:
                all_missing.add(g["name"])
                missing_details.append({
                    "name": g["name"],
                    "emulator": display,
                    "required": g["required"],
                    "source_ref": g["source_ref"],
                })

    if missing_details:
        lines.extend([
            "",
            f"## Missing Files ({len(missing_details)} unique)",
            "",
            "Files loaded by emulators but not available in the repository.",
            "",
            "| File | Emulator | Required | Source |",
            "|------|----------|----------|--------|",
        ])
        for m in sorted(missing_details, key=lambda x: x["name"]):
            req = "yes" if m["required"] else "no"
            lines.append(f"| `{m['name']}` | {m['emulator']} | {req} | {m['source_ref']} |")

    lines.extend(["", f"*Generated on {_timestamp()}*"])
    return "\n".join(lines) + "\n"


def generate_contributing() -> str:
    return """# Contributing - RetroBIOS

## Add a BIOS file

1. Fork this repository
2. Place the file in `bios/Manufacturer/Console/filename`
3. Variants (alternate hashes for the same file): place in `bios/Manufacturer/Console/.variants/`
4. Create a Pull Request - hashes are verified automatically

## Add a platform

1. Create a scraper in `scripts/scraper/` (inherit `BaseScraper`)
2. Read the platform's upstream source code to understand its BIOS check logic
3. Add entry to `platforms/_registry.yml`
4. Generate the platform YAML config
5. Test: `python scripts/verify.py --platform <name>`

## Add an emulator profile

1. Clone the emulator's source code
2. Search for BIOS/firmware loading (grep for `bios`, `rom`, `firmware`, `fopen`)
3. Document every file the emulator loads with source code references
4. Write YAML to `emulators/<name>.yml`
5. Test: `python scripts/cross_reference.py --emulator <name>`

## File conventions

- `bios/Manufacturer/Console/filename` for canonical files
- `bios/Manufacturer/Console/.variants/filename.sha1prefix` for alternate versions
- Files >50 MB go in GitHub release assets (`large-files` release)
- RPG Maker and ScummVM directories are excluded from deduplication

## PR validation

The CI automatically:
- Computes SHA1/MD5/CRC32 of new files
- Checks against known hashes in platform configs
- Reports coverage impact
"""


# ---------------------------------------------------------------------------
# Build cross-reference indexes
# ---------------------------------------------------------------------------

def _build_platform_file_index(coverages: dict) -> dict[str, set]:
    """Map platform_name -> set of declared file names."""
    index = {}
    for name, cov in coverages.items():
        names = set()
        config = cov["config"]
        for system in config.get("systems", {}).values():
            for fe in system.get("files", []):
                names.add(fe.get("name", ""))
        index[name] = names
    return index


def _build_emulator_file_index(profiles: dict) -> dict[str, set]:
    """Map emulator_name -> set of file names it loads."""
    index = {}
    for name, profile in profiles.items():
        if profile.get("type") == "alias":
            continue
        names = {f.get("name", "") for f in profile.get("files", [])}
        index[name] = names
    return index


# ---------------------------------------------------------------------------
# mkdocs.yml nav generator
# ---------------------------------------------------------------------------

def generate_mkdocs_nav(
    coverages: dict,
    manufacturers: dict,
    profiles: dict,
) -> list:
    """Generate the nav section for mkdocs.yml."""
    platform_nav = [{"Overview": "platforms/index.md"}]
    for name in sorted(coverages.keys(), key=lambda x: coverages[x]["platform"]):
        display = coverages[name]["platform"]
        platform_nav.append({display: f"platforms/{name}.md"})

    system_nav = [{"Overview": "systems/index.md"}]
    for mfr in sorted(manufacturers.keys()):
        slug = mfr.lower().replace(" ", "-")
        system_nav.append({mfr: f"systems/{slug}.md"})

    unique_profiles = {k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")}
    emu_nav = [{"Overview": "emulators/index.md"}]
    for name in sorted(unique_profiles.keys()):
        display = unique_profiles[name].get("emulator", name)
        emu_nav.append({display: f"emulators/{name}.md"})

    return [
        {"Home": "index.md"},
        {"Platforms": platform_nav},
        {"Systems": system_nav},
        {"Emulators": emu_nav},
        {"Gap Analysis": "gaps.md"},
        {"Contributing": "contributing.md"},
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate MkDocs site from project data")
    parser.add_argument("--db", default="database.json")
    parser.add_argument("--platforms-dir", default="platforms")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--docs-dir", default=DOCS_DIR)
    args = parser.parse_args()

    db = load_database(args.db)
    docs = Path(args.docs_dir)

    # Clean generated dirs (preserve docs/superpowers/)
    for d in GENERATED_DIRS:
        target = docs / d
        if target.exists():
            shutil.rmtree(target)

    # Ensure output dirs
    for d in GENERATED_DIRS:
        (docs / d).mkdir(parents=True, exist_ok=True)

    # Load registry for platform metadata (logos, etc.)
    registry_path = Path(args.platforms_dir) / "_registry.yml"
    registry = {}
    if registry_path.exists():
        with open(registry_path) as f:
            registry = (yaml.safe_load(f) or {}).get("platforms", {})

    # Load platform configs
    platform_names = [
        p.stem for p in Path(args.platforms_dir).glob("*.yml")
        if not p.name.startswith("_")
    ]

    print("Computing platform coverage...")
    coverages = {}
    for name in sorted(platform_names):
        try:
            cov = compute_coverage(name, args.platforms_dir, db)
            coverages[name] = cov
            print(f"  {cov['platform']}: {cov['present']}/{cov['total']} ({_pct(cov['present'], cov['total'])})")
        except FileNotFoundError as e:
            print(f"  {name}: skipped ({e})", file=sys.stderr)

    # Load emulator profiles
    print("Loading emulator profiles...")
    profiles = _load_emulator_profiles(args.emulators_dir)
    unique_count = sum(1 for p in profiles.values() if p.get("type") != "alias")
    print(f"  {len(profiles)} profiles ({unique_count} unique, {len(profiles) - unique_count} aliases)")

    # Build cross-reference indexes
    platform_files = _build_platform_file_index(coverages)
    emulator_files = _build_emulator_file_index(profiles)

    # Generate home
    print("Generating home page...")
    (docs / "index.md").write_text(generate_home(db, coverages, unique_count, registry))

    # Generate platform pages
    print("Generating platform pages...")
    (docs / "platforms" / "index.md").write_text(generate_platform_index(coverages))
    for name, cov in coverages.items():
        (docs / "platforms" / f"{name}.md").write_text(generate_platform_page(name, cov, registry))

    # Generate system pages
    print("Generating system pages...")
    manufacturers = _group_by_manufacturer(db)
    (docs / "systems" / "index.md").write_text(generate_systems_index(manufacturers))
    for mfr, consoles in manufacturers.items():
        slug = mfr.lower().replace(" ", "-")
        page = generate_system_page(mfr, consoles, platform_files, emulator_files)
        (docs / "systems" / f"{slug}.md").write_text(page)

    # Generate emulator pages
    print("Generating emulator pages...")
    (docs / "emulators" / "index.md").write_text(generate_emulators_index(profiles))
    for name, profile in profiles.items():
        page = generate_emulator_page(name, profile, db, platform_files)
        (docs / "emulators" / f"{name}.md").write_text(page)

    # Generate gap analysis page
    print("Generating gap analysis page...")
    (docs / "gaps.md").write_text(
        generate_gap_analysis(profiles, coverages, db)
    )

    # Generate contributing
    print("Generating contributing page...")
    (docs / "contributing.md").write_text(generate_contributing())

    # Update mkdocs.yml nav section only (avoid yaml.dump round-trip mangling quotes)
    print("Updating mkdocs.yml nav...")
    nav = generate_mkdocs_nav(coverages, manufacturers, profiles)
    nav_yaml = yaml.dump({"nav": nav}, default_flow_style=False, sort_keys=False, allow_unicode=True)

    with open("mkdocs.yml") as f:
        content = f.read()
    # Replace nav section (everything from \nnav: to the next top-level key or EOF)
    import re
    if "\nnav:" in content:
        content = re.sub(r'\nnav:.*', '\n' + nav_yaml.rstrip(), content, count=1, flags=re.DOTALL)
    else:
        content += "\n" + nav_yaml
    with open("mkdocs.yml", "w") as f:
        f.write(content)

    total_pages = (
        1  # home
        + 1 + len(coverages)  # platform index + detail
        + 1 + len(manufacturers)  # system index + detail
        + 1 + len(profiles)  # emulator index + detail
        + 1  # gap analysis
        + 1  # contributing
    )
    print(f"\nGenerated {total_pages} pages in {args.docs_dir}/")


if __name__ == "__main__":
    main()
