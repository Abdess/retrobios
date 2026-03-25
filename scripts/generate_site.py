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
from common import load_database, load_emulator_profiles, load_platform_config
from generate_readme import compute_coverage
from verify import verify_platform

DOCS_DIR = "docs"
SITE_NAME = "RetroBIOS"
REPO_URL = "https://github.com/Abdess/retrobios"
RELEASE_URL = f"{REPO_URL}/releases/latest"
GENERATED_DIRS = ["platforms", "systems", "emulators"]
WIKI_SRC_DIR = "wiki"  # manually maintained wiki sources
SYSTEM_ICON_BASE = "https://raw.githubusercontent.com/libretro/retroarch-assets/master/xmb/systematic/png"

# Global index: maps system_id -> (manufacturer_slug, console_name) for cross-linking
_system_page_map: dict[str, tuple[str, str]] = {}


def _build_system_page_map_from_data(
    manufacturers: dict, coverages: dict, db: dict,
) -> None:
    """Build system_id -> (manufacturer_slug, console_name) mapping.

    Uses platform file paths to trace system_id -> bios directory -> manufacturer page.
    """
    files_db = db.get("files", {})
    by_name = db.get("indexes", {}).get("by_name", {})

    # Build reverse index: filename -> (manufacturer, console) from bios/ structure
    file_to_console: dict[str, tuple[str, str]] = {}
    for mfr, consoles in manufacturers.items():
        for console, entries in consoles.items():
            for entry in entries:
                file_to_console[entry["name"]] = (mfr, console)

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
            for prefix in (f"{mfr_norm}-", "nintendo-", "sega-", "sony-", "snk-", "nec-"):
                if norm.startswith(prefix.replace(f"{mfr_norm}-", "")):
                    pass  # already covered by norm
                key = f"{prefix}{norm}"
                console_norm[key] = entry

    # Map system_id -> (manufacturer, console) via platform file entries
    for cov in coverages.values():
        config = cov["config"]
        for sys_id, system in config.get("systems", {}).items():
            if sys_id in _system_page_map:
                continue
            # Strategy 1: trace via file paths in DB
            for fe in system.get("files", []):
                fname = fe.get("name", "")
                if fname in file_to_console:
                    mfr, console = file_to_console[fname]
                    slug = mfr.lower().replace(" ", "-")
                    _system_page_map[sys_id] = (slug, console)
                    break
            if sys_id in _system_page_map:
                continue
            # Strategy 2: fuzzy match system_id against console directory names
            if sys_id in console_norm:
                _system_page_map[sys_id] = console_norm[sys_id]
            else:
                # Try partial match: "nintendo-wii" matches "Wii" under "Nintendo"
                parts = sys_id.split("-")
                for i in range(len(parts)):
                    suffix = "-".join(parts[i:])
                    if suffix in console_norm:
                        _system_page_map[sys_id] = console_norm[suffix]
                        break


def _system_link(sys_id: str, prefix: str = "") -> str:
    """Generate a markdown link to a system page with anchor."""
    if sys_id in _system_page_map:
        slug, console = _system_page_map[sys_id]
        anchor = console.lower().replace(" ", "-").replace("/", "-")
        return f"[{sys_id}]({prefix}systems/{slug}.md#{anchor})"
    return sys_id


def _render_yaml_value(lines: list[str], val, indent: int = 4) -> None:
    """Render any YAML value as indented markdown."""
    pad = " " * indent
    if isinstance(val, dict):
        for k, v in val.items():
            if isinstance(v, dict):
                lines.append(f"{pad}**{k}:**")
                lines.append("")
                _render_yaml_value(lines, v, indent + 4)
            elif isinstance(v, list):
                lines.append(f"{pad}**{k}:**")
                lines.append("")
                for item in v:
                    if isinstance(item, dict):
                        parts = [f"{ik}: {iv}" for ik, iv in item.items()
                                 if not isinstance(iv, (dict, list))]
                        lines.append(f"{pad}- {', '.join(parts)}")
                    else:
                        lines.append(f"{pad}- {item}")
                lines.append("")
            else:
                # Truncate very long strings in tables
                sv = str(v)
                if len(sv) > 200:
                    sv = sv[:200] + "..."
                lines.append(f"{pad}- **{k}:** {sv}")
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, dict):
                parts = [f"{ik}: {iv}" for ik, iv in item.items()
                         if not isinstance(iv, (dict, list))]
                lines.append(f"{pad}- {', '.join(parts)}")
            else:
                lines.append(f"{pad}- {item}")
    elif isinstance(val, str) and "\n" in val:
        for line in val.split("\n"):
            lines.append(f"{pad}{line}")
    else:
        lines.append(f"{pad}{val}")


def _platform_link(name: str, display: str, prefix: str = "") -> str:
    """Generate a markdown link to a platform page."""
    return f"[{display}]({prefix}platforms/{name}.md)"


def _emulator_link(name: str, prefix: str = "") -> str:
    """Generate a markdown link to an emulator page."""
    return f"[{name}]({prefix}emulators/{name}.md)"


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
# Home page
# ---------------------------------------------------------------------------

def generate_home(db: dict, coverages: dict, profiles: dict,
                   registry: dict | None = None) -> str:
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    ts = _timestamp()

    unique = {k: v for k, v in profiles.items()
              if v.get("type") not in ("alias", "test")}
    emulator_count = len(unique)

    # Classification stats
    classifications: dict[str, int] = {}
    for p in unique.values():
        cls = p.get("core_classification", "unclassified")
        classifications[cls] = classifications.get(cls, 0) + 1

    lines = [
        f"# {SITE_NAME}",
        "",
        "Source-verified BIOS and firmware packs for retrogaming platforms.",
        "",
        "## Quick start",
        "",
        "1. Find your platform in the table below",
        "2. Click **Pack** to download the ZIP",
        "3. Extract to your emulator's BIOS directory",
        "",
        "| Platform | Extract to |",
        "|----------|-----------|",
        "| RetroArch / Lakka | `system/` |",
        "| Batocera | `/userdata/bios/` |",
        "| Recalbox | `/recalbox/share/bios/` |",
        "| RetroBat | `bios/` |",
        "| RetroDECK | `~/retrodeck/bios/` |",
        "| EmuDeck | `Emulation/bios/` |",
        "",
        "---",
        "",
        "## Methodology",
        "",
        "Documentation and metadata can drift from what emulators actually load at runtime.",
        "To keep packs accurate, each file here is checked against the emulator's source code.",
        "",
        "The source code is the primary reference because it reflects actual behavior.",
        "Other sources remain useful but are verified against it:",
        "",
        "1. **Upstream emulator source** - what the original project loads (Dolphin, PCSX2, Mednafen...)",
        "2. **Libretro core source** - the RetroArch port, which may adapt paths or add files",
        "3. **`.info` declarations** - metadata that platforms rely on, checked for accuracy",
        "",
        f"**{emulator_count}** emulators profiled. "
        f"Each profile documents what the code loads, what it validates, "
        f"and where the port differs from the original.",
        "",
        f"**{total_files:,}** files | **{len(coverages)}** platforms | "
        f"**{emulator_count}** emulator profiles | **{_fmt_size(total_size)}** total",
        "",
        "---",
        "",
    ]

    # Platform table
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

    # Emulator classification breakdown
    lines.extend([
        "",
        "## Emulator profiles",
        "",
        "| Classification | Count |",
        "|---------------|-------|",
    ])
    for cls, count in sorted(classifications.items(), key=lambda x: -x[1]):
        lines.append(f"| {cls} | {count} |")

    # Quick links
    lines.extend([
        "",
        "---",
        "",
        f"[Systems](systems/){{ .md-button }} "
        f"[Emulators](emulators/){{ .md-button }} "
        f"[Cross-reference](cross-reference.md){{ .md-button }} "
        f"[Gap Analysis](gaps.md){{ .md-button }} "
        f"[Contributing](contributing.md){{ .md-button .md-button--primary }}",
        "",
        f"*Generated on {ts}.*",
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


def generate_platform_page(name: str, cov: dict, registry: dict | None = None,
                           emulator_files: dict | None = None) -> str:
    config = cov["config"]
    display = cov["platform"]
    mode = cov["mode"]
    pct = _pct(cov["present"], cov["total"])

    logo_url = (registry or {}).get(name, {}).get("logo", "")
    logo_md = f"![{display}]({logo_url}){{ width=48 align=right }}\n\n" if logo_url else ""

    homepage = config.get("homepage", "")
    version = config.get("version", "")
    hash_type = config.get("hash_type", "")
    base_dest = config.get("base_destination", "")

    lines = [
        f"# {display} - {SITE_NAME}",
        "",
        logo_md + f"| | |",
        "|---|---|",
        f"| Verification | {mode} |",
        f"| Hash type | {hash_type} |",
    ]
    if version:
        lines.append(f"| Version | {version} |")
    if base_dest:
        lines.append(f"| BIOS path | `{base_dest}/` |")
    if homepage:
        lines.append(f"| Homepage | [{homepage}]({homepage}) |")
    lines.extend([
        "",
        f"**Coverage:** {cov['present']}/{cov['total']} ({pct}) | "
        f"**Verified:** {cov['verified']} | **Untested:** {cov['untested']} | **Missing:** {cov['missing']}",
        "",
        f"[Download {display} Pack]({RELEASE_URL}){{ .md-button }}",
        "",
    ])

    # Build lookup from config file entries (has hashes/sizes)
    config_files: dict[str, dict] = {}
    for sys_id, system in config.get("systems", {}).items():
        for fe in system.get("files", []):
            fname = fe.get("name", "")
            if fname:
                config_files[fname] = fe

    # Group details by system
    by_system: dict[str, list] = {}
    for d in cov["details"]:
        sys_id = d.get("system", "unknown")
        by_system.setdefault(sys_id, []).append(d)

    # System summary table (quick navigation)
    lines.extend([
        "## Systems overview",
        "",
        "| System | Files | Status | Emulators |",
        "|--------|-------|--------|-----------|",
    ])
    for sys_id, files in sorted(by_system.items()):
        ok_count = sum(1 for f in files if f["status"] == "ok")
        total = len(files)
        non_ok = total - ok_count
        status = "OK" if non_ok == 0 else f"{non_ok} issue{'s' if non_ok > 1 else ''}"
        sys_emus = []
        if emulator_files:
            for emu_name, emu_data in emulator_files.items():
                if sys_id in emu_data.get("systems", set()):
                    sys_emus.append(emu_name)
        emu_str = ", ".join(sys_emus[:3])
        if len(sys_emus) > 3:
            emu_str += f" +{len(sys_emus) - 3}"
        anchor = sys_id.replace(" ", "-")
        lines.append(f"| [{sys_id}](#{anchor}) | {ok_count}/{total} | {status} | {emu_str} |")
    lines.append("")

    # Per-system detail sections (collapsible for large platforms)
    use_collapsible = len(by_system) > 10

    for sys_id, files in sorted(by_system.items()):
        ok_count = sum(1 for f in files if f["status"] == "ok")
        total = len(files)

        sys_emus = []
        if emulator_files:
            for emu_name, emu_data in emulator_files.items():
                if sys_id in emu_data.get("systems", set()):
                    sys_emus.append(emu_name)

        sys_link = _system_link(sys_id, "../")

        anchor = sys_id.replace(" ", "-")
        if use_collapsible:
            status_tag = "OK" if ok_count == total else f"{total - ok_count} issues"
            lines.append(f"<a id=\"{anchor}\"></a>")
            lines.append(f"??? note \"{sys_id} ({ok_count}/{total} - {status_tag})\"")
            lines.append("")
            pad = "    "
        else:
            lines.append(f"## {sys_link}")
            lines.append("")
            pad = ""

        lines.append(f"{pad}{ok_count}/{total} files verified")
        if sys_emus:
            emu_links = ", ".join(_emulator_link(e, "../") for e in sorted(sys_emus))
            lines.append(f"{pad}Emulators: {emu_links}")
        lines.append("")

        # File listing
        for f in sorted(files, key=lambda x: x["name"]):
            status = f["status"]
            fname = f["name"]
            cfg_entry = config_files.get(fname, {})
            sha1 = cfg_entry.get("sha1", f.get("sha1", ""))
            md5 = cfg_entry.get("md5", f.get("expected_md5", ""))
            size = cfg_entry.get("size", f.get("size", 0))

            if status == "ok":
                status_display = "OK"
            elif status == "untested":
                reason = f.get("reason", "")
                status_display = f"untested: {reason}" if reason else "untested"
            elif status == "missing":
                status_display = "**missing**"
            else:
                status_display = status

            size_str = _fmt_size(size) if size else ""
            details = [status_display]
            if size_str:
                details.append(size_str)

            lines.append(f"{pad}- `{fname}` - {', '.join(details)}")
            # Show full hashes on a sub-line (useful for copy-paste)
            if sha1 or md5:
                hash_parts = []
                if sha1:
                    hash_parts.append(f"SHA1: `{sha1}`")
                if md5:
                    hash_parts.append(f"MD5: `{md5}`")
                lines.append(f"{pad}    {' | '.join(hash_parts)}")

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
    emulator_files: dict[str, dict],
) -> str:
    slug = manufacturer.lower().replace(" ", "-")
    lines = [
        f"# {manufacturer} - {SITE_NAME}",
        "",
    ]

    for console_name in sorted(consoles.keys()):
        files = consoles[console_name]
        icon_name = f"{manufacturer} - {console_name}".replace("/", " ")
        icon_url = f"{SYSTEM_ICON_BASE}/{icon_name.replace(' ', '%20')}.png"
        lines.append(f"## ![{console_name}]({icon_url}){{ width=24 }} {console_name}")
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
            emus = sorted(e for e, data in emulator_files.items() if name in data.get("files", set()))

            lines.append(f"**`{name}`** ({size})")
            lines.append("")
            lines.append(f"- SHA1: `{sha1_full}`")
            lines.append(f"- MD5: `{md5_full}`")
            if plats:
                plat_links = [_platform_link(p, p, "../") for p in plats]
                lines.append(f"- Platforms: {', '.join(plat_links)}")
            if emus:
                emu_links = [_emulator_link(e, "../") for e in emus]
                lines.append(f"- Emulators: {', '.join(emu_links)}")
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
    unique = {k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")}
    aliases = {k: v for k, v in profiles.items() if v.get("type") == "alias"}

    # Group by classification
    by_class: dict[str, list[tuple[str, dict]]] = {}
    for name in sorted(unique.keys()):
        p = unique[name]
        cls = p.get("core_classification", "other")
        by_class.setdefault(cls, []).append((name, p))

    total_files = sum(len(p.get("files", [])) for p in unique.values())

    lines = [
        f"# Emulators - {SITE_NAME}",
        "",
        f"**{len(unique)}** emulator profiles, **{total_files}** files total, **{len(aliases)}** aliases.",
        "",
        "| Classification | Count | Description |",
        "|---------------|-------|-------------|",
    ]

    cls_desc = {
        "official_port": "Same author maintains both standalone and libretro",
        "community_fork": "Third-party port to libretro",
        "pure_libretro": "Built for libretro, no standalone version",
        "game_engine": "Game engine reimplementation",
        "enhanced_fork": "Fork with added features",
        "frozen_snapshot": "Frozen at an old version",
        "embedded_hle": "All ROMs compiled into binary",
        "launcher": "Launches an external emulator",
        "other": "Unclassified",
    }

    cls_order = ["official_port", "community_fork", "pure_libretro",
                 "game_engine", "enhanced_fork", "frozen_snapshot",
                 "embedded_hle", "launcher", "other"]

    for cls in cls_order:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        desc = cls_desc.get(cls, "")
        lines.append(f"| [{cls}](#{cls}) | {len(entries)} | {desc} |")
    lines.append("")

    # Per-classification sections
    for cls in cls_order:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        lines.extend([
            f"## {cls}",
            "",
            "| Engine | Systems | Files |",
            "|--------|---------|-------|",
        ])

        for name, p in entries:
            emu_name = p.get("emulator", name)
            systems = p.get("systems", [])
            files = p.get("files", [])
            sys_str = ", ".join(systems[:3])
            if len(systems) > 3:
                sys_str += f" +{len(systems) - 3}"
            lines.append(
                f"| [{emu_name}]({name}.md) | {sys_str} | {len(files)} |"
            )
        lines.append("")

    if aliases:
        lines.extend(["## Aliases", ""])
        lines.append("| Core | Points to |")
        lines.append("|------|-----------|")
        for name in sorted(aliases.keys()):
            parent = aliases[name].get("alias_of", aliases[name].get("bios_identical_to", "unknown"))
            lines.append(f"| {name} | [{parent}]({parent}.md) |")
        lines.append("")

    return "\n".join(lines) + "\n"


def generate_emulator_page(name: str, profile: dict, db: dict,
                           platform_files: dict | None = None) -> str:
    if profile.get("type") == "alias":
        parent = profile.get("alias_of", profile.get("bios_identical_to", "unknown"))
        return (
            f"# {name} - {SITE_NAME}\n\n"
            f"This core uses the same firmware as **{parent}**.\n\n"
            f"See [{parent}]({parent}.md) for details.\n"
        )

    emu_name = profile.get("emulator", name)
    emu_type = profile.get("type", "unknown")
    classification = profile.get("core_classification", "")
    source = profile.get("source", "")
    upstream = profile.get("upstream", "")
    version = profile.get("core_version", "unknown")
    display = profile.get("display_name", emu_name)
    profiled = profile.get("profiled_date", "unknown")
    systems = profile.get("systems", [])
    cores = profile.get("cores", [name])
    files = profile.get("files", [])
    notes_raw = profile.get("notes", profile.get("note", ""))
    notes = str(notes_raw).strip() if notes_raw and not isinstance(notes_raw, dict) else ""
    exclusion = profile.get("exclusion_note", "")
    data_dirs = profile.get("data_directories", [])

    lines = [
        f"# {emu_name} - {SITE_NAME}",
        "",
        f"| | |",
        f"|---|---|",
        f"| Type | {emu_type} |",
    ]
    if classification:
        lines.append(f"| Classification | {classification} |")
    if source:
        lines.append(f"| Source | [{source}]({source}) |")
    if upstream and upstream != source:
        lines.append(f"| Upstream | [{upstream}]({upstream}) |")
    lines.append(f"| Version | {version} |")
    lines.append(f"| Profiled | {profiled} |")
    if cores:
        lines.append(f"| Cores | {', '.join(str(c) for c in cores)} |")
    if systems:
        sys_links = [_system_link(s, "../") for s in systems]
        lines.append(f"| Systems | {', '.join(sys_links)} |")
    mame_ver = profile.get("mame_version", "")
    if mame_ver:
        lines.append(f"| MAME version | {mame_ver} |")
    author = profile.get("author", "")
    if author:
        lines.append(f"| Author | {author} |")
    based_on = profile.get("based_on", "")
    if based_on:
        lines.append(f"| Based on | {based_on} |")
    # Additional metadata fields (scalar values only -complex ones go to collapsible sections)
    for field, label in [
        ("core", "Core ID"), ("core_name", "Core name"),
        ("bios_size", "BIOS size"), ("bios_directory", "BIOS directory"),
        ("bios_detection", "BIOS detection"), ("bios_selection", "BIOS selection"),
        ("firmware_file", "Firmware file"), ("firmware_source", "Firmware source"),
        ("firmware_install", "Firmware install"), ("firmware_detection", "Firmware detection"),
        ("resources_directory", "Resources directory"), ("rom_path", "ROM path"),
        ("game_count", "Game count"), ("verification", "Verification mode"),
        ("source_ref", "Source ref"), ("analysis_date", "Analysis date"),
        ("analysis_commit", "Analysis commit"),
    ]:
        val = profile.get(field)
        if val is None or val == "" or isinstance(val, (dict, list)):
            continue
        if isinstance(val, str) and val.startswith("http"):
            lines.append(f"| {label} | [{val}]({val}) |")
        else:
            lines.append(f"| {label} | {val} |")
    lines.append("")

    # Platform-specific details (rich structured data)
    platform_details = profile.get("platform_details")
    if platform_details and isinstance(platform_details, dict):
        lines.extend(["???+ info \"Platform details\"", ""])
        for pk, pv in platform_details.items():
            if isinstance(pv, dict):
                lines.append(f"    **{pk}:**")
                for sk, sv in pv.items():
                    lines.append(f"    - {sk}: {sv}")
            elif isinstance(pv, list):
                lines.append(f"    **{pk}:** {', '.join(str(x) for x in pv)}")
            else:
                lines.append(f"    **{pk}:** {pv}")
        lines.append("")

    # All remaining structured data blocks as collapsible sections
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
        lines.append(f"???+ abstract \"{label}\"")
        lines.append("")
        _render_yaml_value(lines, val, indent=4)
        lines.append("")

    # Notes
    if notes:
        indented = notes.replace("\n", "\n    ")
        lines.extend(["???+ note \"Technical notes\"",
                       f"    {indented}",
                       ""])

    if not files:
        lines.append("No BIOS or firmware files required.")
        if exclusion:
            lines.extend([
                "",
                f"!!! info \"Why no files\"",
                f"    {exclusion}",
            ])
    else:
        by_name = db.get("indexes", {}).get("by_name", {})
        files_db = db.get("files", {})

        # Stats by category
        bios_files = [f for f in files if f.get("category", "bios") == "bios"]
        game_data = [f for f in files if f.get("category") == "game_data"]
        bios_zips = [f for f in files if f.get("category") == "bios_zip"]

        in_repo_count = sum(1 for f in files if f.get("name", "") in by_name)
        missing_count = len(files) - in_repo_count
        req_count = sum(1 for f in files if f.get("required"))
        opt_count = len(files) - req_count
        hle_count = sum(1 for f in files if f.get("hle_fallback"))

        parts = [f"**{len(files)} files**"]
        parts.append(f"{req_count} required, {opt_count} optional")
        parts.append(f"{in_repo_count} in repo, {missing_count} missing")
        if hle_count:
            parts.append(f"{hle_count} with HLE fallback")
        lines.append(" | ".join(parts))

        if game_data or bios_zips:
            cats = []
            if bios_files:
                cats.append(f"{len(bios_files)} BIOS")
            if game_data:
                cats.append(f"{len(game_data)} game data")
            if bios_zips:
                cats.append(f"{len(bios_zips)} BIOS ZIPs")
            lines.append(f"Categories: {', '.join(cats)}")
        lines.append("")

        # File table
        for f in files:
            fname = f.get("name", "")
            required = f.get("required", False)
            in_repo = fname in by_name
            source_ref = f.get("source_ref", "")
            mode = f.get("mode", "")
            hle = f.get("hle_fallback", False)
            aliases = f.get("aliases", [])
            category = f.get("category", "")
            validation = f.get("validation", [])
            size = f.get("size")
            fnote = f.get("note", f.get("notes", ""))
            storage = f.get("storage", "")
            fmd5 = f.get("md5", "")
            fsha1 = f.get("sha1", "")
            fcrc32 = f.get("crc32", "")
            fsha256 = f.get("sha256", "")
            fadler32 = f.get("known_hash_adler32", "")
            fmin = f.get("min_size")
            fmax = f.get("max_size")
            desc = f.get("description", "")
            region = f.get("region", "")
            archive = f.get("archive", "")
            fpath = f.get("path", "")
            fsystem = f.get("system", "")
            priority = f.get("priority")
            fast_boot = f.get("fast_boot")
            bundled = f.get("bundled", False)
            embedded = f.get("embedded", False)
            has_builtin = f.get("has_builtin", False)
            contents = f.get("contents", [])
            config_key = f.get("config_key", "")
            dest = f.get("dest", f.get("destination", ""))
            ftype = f.get("type", "")
            fpattern = f.get("pattern", "")
            region_check = f.get("region_check")
            size_note = f.get("size_note", "")
            size_options = f.get("size_options", [])
            size_range = f.get("size_range", "")

            # Status badges
            badges = []
            if required:
                badges.append("**required**")
            else:
                badges.append("optional")
            if hle:
                badges.append("HLE available")
            if mode:
                badges.append(mode)
            if category and category != "bios":
                badges.append(category)
            if region:
                badges.append(", ".join(region) if isinstance(region, list) else str(region))
            if storage and storage != "embedded":
                badges.append(storage)
            if bundled:
                badges.append("bundled in binary")
            if embedded:
                badges.append("embedded")
            if has_builtin:
                badges.append("has built-in fallback")
            if archive:
                badges.append(f"in `{archive}`")
            if ftype and ftype != "bios":
                badges.append(ftype)
            if not in_repo:
                badges.append("missing from repo")

            lines.append(f"**`{fname}`** -{', '.join(badges)}")
            if desc:
                lines.append(f": {desc}")
            lines.append("")

            details = []
            if fpath and fpath != fname:
                details.append(f"Path: `{fpath}`")
            if fsystem:
                details.append(f"System: {_system_link(fsystem, '../')}")
            if size:
                size_str = _fmt_size(size)
                if fmin or fmax:
                    bounds = []
                    if fmin:
                        bounds.append(f"min {_fmt_size(fmin)}")
                    if fmax:
                        bounds.append(f"max {_fmt_size(fmax)}")
                    size_str += f" ({', '.join(bounds)})"
                details.append(f"Size: {size_str}")
            elif fmin or fmax:
                bounds = []
                if fmin:
                    bounds.append(f"min {_fmt_size(fmin)}")
                if fmax:
                    bounds.append(f"max {_fmt_size(fmax)}")
                details.append(f"Size: {', '.join(bounds)}")
            if fsha1:
                details.append(f"SHA1: `{fsha1}`")
            if fmd5:
                details.append(f"MD5: `{fmd5}`")
            if fcrc32:
                details.append(f"CRC32: `{fcrc32}`")
            if fsha256:
                details.append(f"SHA256: `{fsha256}`")
            if fadler32:
                details.append(f"Adler32: `{fadler32}`")
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
            if source_ref:
                details.append(f"Source: `{source_ref}`")
            if platform_files:
                plats = sorted(p for p, names in platform_files.items() if fname in names)
                if plats:
                    plat_links = [_platform_link(p, p, "../") for p in plats]
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
            if size_options:
                details.append(f"Size options: {', '.join(_fmt_size(s) for s in size_options)}")
            if size_range:
                details.append(f"Size range: {size_range}")

            if details:
                for d in details:
                    lines.append(f"- {d}")
            if fnote:
                lines.append(f"- {fnote}")
            if contents:
                lines.append(f"- Contents ({len(contents)} entries):")
                for c in contents[:10]:
                    if isinstance(c, dict):
                        cname = c.get("name", "")
                        cdesc = c.get("description", "")
                        csize = c.get("size", "")
                        parts = [f"`{cname}`"]
                        if cdesc:
                            parts.append(cdesc)
                        if csize:
                            parts.append(_fmt_size(csize))
                        lines.append(f"    - {' -'.join(parts)}")
                    else:
                        lines.append(f"    - {c}")
                if len(contents) > 10:
                    lines.append(f"    - ... and {len(contents) - 10} more")
            lines.append("")

    # Data directories
    if data_dirs:
        lines.extend(["## Data directories", ""])
        for dd in data_dirs:
            ref = dd.get("ref", "")
            dest = dd.get("destination", "")
            lines.append(f"- `{ref}` >`{dest}`")
        lines.append("")

    lines.extend([f"*Generated on {_timestamp()}*"])
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

    # Build reverse map: emulator -> platforms that use it (via cores: field)
    from common import resolve_platform_cores
    emu_to_platforms: dict[str, set[str]] = {}
    unique_profiles = {k: v for k, v in profiles.items()
                       if v.get("type") not in ("alias", "test")}
    for pname in coverages:
        config = coverages[pname]["config"]
        matched = resolve_platform_cores(config, unique_profiles)
        for emu_name in matched:
            emu_to_platforms.setdefault(emu_name, set()).add(pname)

    if missing_details:
        req_missing = [m for m in missing_details if m["required"]]
        opt_missing = [m for m in missing_details if not m["required"]]

        lines.extend([
            "",
            f"## Missing Files ({len(missing_details)} unique, {len(req_missing)} required)",
            "",
            "Files loaded by emulators but not available in the repository.",
            "Adding these files would improve pack completeness.",
            "",
        ])

        if req_missing:
            lines.extend([
                "### Required (highest priority)",
                "",
                "These files are needed for the emulator to function.",
                "",
                "| File | Emulator | Affects platforms | Source |",
                "|------|----------|------------------|--------|",
            ])
            for m in sorted(req_missing, key=lambda x: x["name"]):
                emu_key = next((k for k, v in profiles.items()
                               if v.get("emulator") == m["emulator"]), "")
                plats = sorted(emu_to_platforms.get(emu_key, set()))
                plat_str = ", ".join(plats) if plats else "-"
                lines.append(f"| `{m['name']}` | {m['emulator']} | {plat_str} | {m['source_ref']} |")
            lines.append("")

        if opt_missing:
            lines.extend([
                "### Optional",
                "",
                "| File | Emulator | Source |",
                "|------|----------|--------|",
            ])
            for m in sorted(opt_missing, key=lambda x: x["name"]):
                lines.append(f"| `{m['name']}` | {m['emulator']} | {m['source_ref']} |")
            lines.append("")

    lines.extend(["", f"*Generated on {_timestamp()}*"])
    return "\n".join(lines) + "\n"


def generate_cross_reference(
    coverages: dict,
    profiles: dict,
) -> str:
    """Generate cross-reference: Platform -> Core -> Systems -> Upstream."""
    unique = {k: v for k, v in profiles.items()
              if v.get("type") not in ("alias", "test")}

    # Build core -> profile lookup by core name
    core_to_profile: dict[str, str] = {}
    for pname, p in unique.items():
        for core in p.get("cores", [pname]):
            core_to_profile[str(core)] = pname

    lines = [
        f"# Cross-reference - {SITE_NAME}",
        "",
        "Platform >Core >Systems >Upstream emulator.",
        "",
        "The libretro core is a port of the upstream emulator. "
        "Files, features, and validation may differ between the two.",
        "",
    ]

    # Per platform
    for pname in sorted(coverages.keys(), key=lambda x: coverages[x]["platform"]):
        cov = coverages[pname]
        display = cov["platform"]
        config = cov["config"]
        platform_cores = config.get("cores", [])

        lines.append(f"??? abstract \"[{display}](platforms/{pname}.md)\"")
        lines.append("")

        # Resolve which profiles this platform uses
        if platform_cores == "all_libretro":
            matched = {k: v for k, v in unique.items()
                       if "libretro" in v.get("type", "")}
        elif isinstance(platform_cores, list):
            matched = {}
            for cname in platform_cores:
                cname_str = str(cname)
                if cname_str in unique:
                    matched[cname_str] = unique[cname_str]
                elif cname_str in core_to_profile:
                    pkey = core_to_profile[cname_str]
                    matched[pkey] = unique[pkey]
        else:
            # Fallback: system intersection
            psystems = set(config.get("systems", {}).keys())
            matched = {k: v for k, v in unique.items()
                       if set(v.get("systems", [])) & psystems}

        if platform_cores == "all_libretro":
            lines.append(f"    **{len(matched)} cores** (all libretro)")
        else:
            lines.append(f"    **{len(matched)} cores**")
        lines.append("")

        lines.append("    | Core | Classification | Systems | Files | Upstream |")
        lines.append("    |------|---------------|---------|-------|----------|")

        for emu_name in sorted(matched.keys()):
            p = matched[emu_name]
            emu_display = p.get("emulator", emu_name)
            cls = p.get("core_classification", "-")
            emu_type = p.get("type", "")
            upstream = p.get("upstream", "")
            source = p.get("source", "")
            systems = p.get("systems", [])
            files = p.get("files", [])

            sys_str = ", ".join(systems[:3])
            if len(systems) > 3:
                sys_str += f" +{len(systems) - 3}"

            file_count = len(files)
            # Count mode divergences
            libretro_only = sum(1 for f in files if f.get("mode") == "libretro")
            standalone_only = sum(1 for f in files if f.get("mode") == "standalone")
            file_str = str(file_count)
            if libretro_only or standalone_only:
                parts = []
                if libretro_only:
                    parts.append(f"{libretro_only} libretro-only")
                if standalone_only:
                    parts.append(f"{standalone_only} standalone-only")
                file_str += f" ({', '.join(parts)})"

            upstream_display = "-"
            if upstream:
                upstream_short = upstream.replace("https://github.com/", "")
                upstream_display = f"[{upstream_short}]({upstream})"
            elif source:
                source_short = source.replace("https://github.com/", "")
                upstream_display = f"[{source_short}]({source})"

            lines.append(
                f"    | [{emu_display}](emulators/{emu_name}.md) | {cls} | "
                f"{sys_str} | {file_str} | {upstream_display} |"
            )

        lines.append("")

    # Reverse view: by upstream emulator
    lines.extend([
        "## By upstream emulator",
        "",
        "| Upstream | Cores | Classification | Platforms |",
        "|----------|-------|---------------|-----------|",
    ])

    # Group profiles by upstream
    by_upstream: dict[str, list[str]] = {}
    for emu_name, p in sorted(unique.items()):
        upstream = p.get("upstream", p.get("source", ""))
        if upstream:
            by_upstream.setdefault(upstream, []).append(emu_name)

    # Build platform membership per core
    platform_membership: dict[str, set[str]] = {}
    for pname, cov in coverages.items():
        config = cov["config"]
        pcores = config.get("cores", [])
        if pcores == "all_libretro":
            for k, v in unique.items():
                if "libretro" in v.get("type", ""):
                    platform_membership.setdefault(k, set()).add(pname)
        elif isinstance(pcores, list):
            for cname in pcores:
                cname_str = str(cname)
                if cname_str in unique:
                    platform_membership.setdefault(cname_str, set()).add(pname)
                elif cname_str in core_to_profile:
                    pkey = core_to_profile[cname_str]
                    platform_membership.setdefault(pkey, set()).add(pname)

    for upstream_url in sorted(by_upstream.keys()):
        cores = by_upstream[upstream_url]
        upstream_short = upstream_url.replace("https://github.com/", "")
        classifications = set()
        all_plats: set[str] = set()
        for c in cores:
            classifications.add(unique[c].get("core_classification", "-"))
            all_plats.update(platform_membership.get(c, set()))

        cls_str = ", ".join(sorted(classifications))
        plat_str = ", ".join(sorted(all_plats)) if all_plats else "-"
        core_links = ", ".join(f"[{c}](emulators/{c}.md)" for c in sorted(cores))

        lines.append(
            f"| [{upstream_short}]({upstream_url}) | {core_links} | "
            f"{cls_str} | {plat_str} |"
        )

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
# Wiki pages
# ---------------------------------------------------------------------------

def generate_wiki_index() -> str:
    """Generate wiki landing page."""
    return f"""# Wiki - {SITE_NAME}

Technical documentation for the RetroBIOS toolchain.

## Pages

- **[Architecture](architecture.md)** - directory structure, data flow, platform inheritance, pack grouping, security, edge cases, CI workflows
- **[Tools](tools.md)** - CLI reference for every script, pipeline usage, scrapers
- **[Profiling guide](profiling.md)** - how to create an emulator profile from source code, step by step, with YAML field reference
- **[Data model](data-model.md)** - database.json structure, indexes, file resolution order, YAML formats

## For users

If you just want to download BIOS packs, see the [home page](../index.md).

## For contributors

Start with the [profiling guide](profiling.md) to understand how emulator profiles are built,
then see [contributing](../contributing.md) for submission guidelines.
"""


def generate_wiki_architecture() -> str:
    """Generate architecture overview from codebase structure."""
    lines = [
        f"# Architecture - {SITE_NAME}",
        "",
        "## Directory structure",
        "",
        "```",
        "bios/                    BIOS and firmware files, organized by Manufacturer/Console/",
        "  Manufacturer/Console/  canonical files (one per unique content)",
        "  .variants/             alternate versions (different hash, same purpose)",
        "emulators/               one YAML profile per core (285 profiles)",
        "platforms/               one YAML config per platform (scraped from upstream)",
        "  _shared.yml            shared file groups across platforms",
        "  _registry.yml          platform metadata (logos, scrapers, status)",
        "  _data_dirs.yml         data directory definitions (Dolphin Sys, PPSSPP...)",
        "scripts/                 all tooling (Python, pyyaml only dependency)",
        "  scraper/               upstream scrapers (libretro, batocera, recalbox...)",
        "data/                    cached data directories (not BIOS, fetched at build)",
        "schemas/                 JSON schemas for validation",
        "tests/                   E2E test suite with synthetic fixtures",
        "dist/                    generated packs (gitignored)",
        ".cache/                  hash cache and large file downloads (gitignored)",
        "```",
        "",
        "## Data flow",
        "",
        "```",
        "Upstream sources          Scrapers parse       generate_db.py scans",
        "  System.dat (libretro)   + fetch versions     bios/ on disk",
        "  batocera-systems                             builds database.json",
        "  es_bios.xml (recalbox)                       (SHA1 primary key,",
        "  core-info .info files                         indexes: by_md5, by_name,",
        "                                                by_crc32, by_path_suffix)",
        "",
        "emulators/*.yml          verify.py checks      generate_pack.py resolves",
        "  source-verified         platform-native       files by hash, builds ZIP",
        "  from code               verification          packs per platform",
        "```",
        "",
        "## Three layers of data",
        "",
        "| Layer | Source | Role |",
        "|-------|--------|------|",
        "| Platform YAML | Scraped from upstream | What the platform declares it needs |",
        "| `_shared.yml` | Curated | Shared files across platforms, reflects actual behavior |",
        "| Emulator profiles | Source-verified | What the code actually loads. Used for cross-reference and gap detection |",
        "",
        "The pack combines platform baseline (layer 1) with core requirements (layer 3).",
        "Neither too much (no files from unused cores) nor too few (no missing files for active cores).",
        "",
        "## Pack grouping",
        "",
        "Platforms that produce identical packs are grouped automatically.",
        "RetroArch and Lakka share the same files and `base_destination` (`system/`),",
        "so they produce one combined pack (`RetroArch_Lakka_BIOS_Pack.zip`).",
        "RetroPie uses `BIOS/` as base path, so it gets a separate pack.",
        "",
        "## Storage tiers",
        "",
        "| Tier | Meaning |",
        "|------|---------|",
        "| `embedded` (default) | file is in the `bios/` directory, included in packs |",
        "| `external` | file has a `source_url`, downloaded at pack build time |",
        "| `user_provided` | user must provide the file (instructions included in pack) |",
        "",
        "## Verification severity",
        "",
        "How missing or mismatched files are reported:",
        "",
        "| Mode | required + missing | optional + missing | hash mismatch |",
        "|------|-------------------|-------------------|--------------|",
        "| existence | WARNING | INFO | N/A |",
        "| md5 | CRITICAL | WARNING | UNTESTED |",
        "",
        "Files with `hle_fallback: true` are downgraded to INFO when missing",
        "(the emulator has a software fallback).",
        "",
        "## Discrepancy detection",
        "",
        "When a file passes platform verification (MD5 match) but fails",
        "emulator-level validation (wrong CRC32, wrong size), a DISCREPANCY is reported.",
        "The pack generator searches the repo for a variant that satisfies both.",
        "If none exists, the platform version is kept.",
        "",
        "## Security",
        "",
        "- `safe_extract_zip()` prevents zip-slip path traversal attacks",
        "- `deterministic_zip` rebuilds MAME ZIPs so same ROMs always produce the same hash",
        "- `crypto_verify.py` and `sect233r1.py` verify 3DS RSA-2048 signatures and AES-128-CBC integrity",
        "- ZIP inner ROM verification via `checkInsideZip()` replicates Batocera's behavior",
        "- `md5_composite()` replicates Recalbox's composite ZIP hash",
        "",
        "## Edge cases",
        "",
        "| Case | Handling |",
        "|------|---------|",
        "| Batocera truncated MD5 (29 chars) | prefix match in resolution |",
        "| `zippedFile` entries | MD5 is of the ROM inside the ZIP, not the ZIP itself |",
        "| Regional variants (same filename) | `by_path_suffix` index disambiguates |",
        "| MAME BIOS ZIPs | `contents` field documents inner structure |",
        "| RPG Maker/ScummVM | excluded from dedup (NODEDUP) to preserve directory structure |",
        "| `strip_components` in data dirs | flattens cache prefix to match expected path |",
        "| case-insensitive dedup | prevents `font.rom` + `FONT.ROM` conflicts on Windows/macOS |",
        "",
        "## Platform inheritance",
        "",
        "Platform configs support `inherits:` to share definitions.",
        "Lakka inherits from RetroArch, RetroPie inherits from RetroArch with `base_destination: BIOS`.",
        "`overrides:` allows child platforms to modify specific systems from the parent.",
        "",
        "Core resolution (`resolve_platform_cores`) uses three strategies:",
        "",
        "- `cores: all_libretro` - include all profiles with `libretro` in their type",
        "- `cores: [list]` - include only named profiles",
        "- `cores:` absent - fallback to system ID intersection between platform and profiles",
        "",
        "## MAME clone map",
        "",
        "`_mame_clones.json` at repo root maps MAME clone ROM names to their canonical parent.",
        "When a clone ZIP was deduplicated, `resolve_local_file` uses this map to find the canonical file.",
        "",
        "## Tests",
        "",
        "`tests/test_e2e.py` contains 75 end-to-end tests with synthetic fixtures.",
        "Covers: file resolution, verification, severity, cross-reference, aliases,",
        "inheritance, shared groups, data dirs, storage tiers, HLE, launchers,",
        "platform grouping, core resolution (3 strategies + alias exclusion).",
        "",
        "```bash",
        "python -m unittest tests.test_e2e -v",
        "```",
        "",
        "## CI workflows",
        "",
        "| Workflow | File | Trigger | Role |",
        "|----------|------|---------|------|",
        "| Build & Release | `build.yml` | `workflow_dispatch` (manual) | restore large files, build packs, deploy site, create GitHub release |",
        "| PR Validation | `validate.yml` | pull request on `bios/`/`platforms/` | validate BIOS hashes, schema check, run tests, auto-label PR |",
        "| Weekly Sync | `watch.yml` | cron (Monday 6 AM UTC) + manual | scrape upstream sources, detect changes, create update PR |",
        "",
        "Build workflow has a 7-day rate limit between releases and keeps the 3 most recent.",
        "",
        "## License",
        "",
        "See `LICENSE` at repo root. Files are provided for personal backup and archival.",
        "",
    ]
    return "\n".join(lines) + "\n"


def generate_wiki_tools() -> str:
    """Generate tool reference from script docstrings and argparse."""
    lines = [
        f"# Tools - {SITE_NAME}",
        "",
        "All tools are Python scripts in `scripts/`. Single dependency: `pyyaml`.",
        "",
        "## Pipeline",
        "",
        "Run everything in sequence:",
        "",
        "```bash",
        "python scripts/pipeline.py --offline          # DB + verify + packs + readme + site",
        "python scripts/pipeline.py --offline --skip-packs  # DB + verify only",
        "python scripts/pipeline.py --skip-docs        # skip readme + site generation",
        "```",
        "",
        "## Individual tools",
        "",
        "### generate_db.py",
        "",
        "Scan `bios/` and build `database.json` with multi-indexed lookups.",
        "Large files in `.gitignore` are preserved from the existing database",
        "and downloaded from GitHub release assets if not cached locally.",
        "",
        "```bash",
        "python scripts/generate_db.py --force --bios-dir bios --output database.json",
        "```",
        "",
        "### verify.py",
        "",
        "Check BIOS coverage for each platform using its native verification mode.",
        "",
        "```bash",
        "python scripts/verify.py --all                # all platforms",
        "python scripts/verify.py --platform batocera  # single platform",
        "python scripts/verify.py --emulator dolphin   # single emulator",
        "python scripts/verify.py --system atari-lynx  # single system",
        "```",
        "",
        "Verification modes per platform:",
        "",
        "| Platform | Mode | Logic |",
        "|----------|------|-------|",
        "| RetroArch, Lakka, RetroPie | existence | file present = OK |",
        "| Batocera, RetroBat | md5 | MD5 hash match |",
        "| Recalbox | md5 | MD5 multi-hash, 3 severity levels |",
        "| EmuDeck | md5 | MD5 whitelist per system |",
        "",
        "### generate_pack.py",
        "",
        "Build platform-specific BIOS ZIP packs.",
        "",
        "```bash",
        "python scripts/generate_pack.py --all --output-dir dist/",
        "python scripts/generate_pack.py --platform batocera",
        "python scripts/generate_pack.py --emulator dolphin",
        "python scripts/generate_pack.py --system atari-lynx",
        "```",
        "",
        "Packs include platform baseline files plus files required by the platform's cores.",
        "When a file passes platform verification but fails emulator validation,",
        "the tool searches for a variant that satisfies both.",
        "If none exists, the platform version is kept and the discrepancy is reported.",
        "",
        "### cross_reference.py",
        "",
        "Compare emulator profiles against platform configs.",
        "Reports files that cores need but platforms don't declare.",
        "",
        "```bash",
        "python scripts/cross_reference.py                    # all",
        "python scripts/cross_reference.py --emulator dolphin # single",
        "```",
        "",
        "### refresh_data_dirs.py",
        "",
        "Fetch data directories (Dolphin Sys, PPSSPP assets, blueMSX databases)",
        "from upstream repositories into `data/`.",
        "",
        "```bash",
        "python scripts/refresh_data_dirs.py",
        "python scripts/refresh_data_dirs.py --key dolphin-sys --force",
        "```",
        "",
        "### Other tools",
        "",
        "| Script | Purpose |",
        "|--------|---------|",
        "| `dedup.py` | Deduplicate `bios/`, move duplicates to `.variants/`. RPG Maker and ScummVM excluded (NODEDUP) |",
        "| `validate_pr.py` | Validate BIOS files in pull requests |",
        "| `auto_fetch.py` | Fetch missing BIOS files from known sources |",
        "| `list_platforms.py` | List active platforms (used by CI) |",
        "| `download.py` | Download packs from GitHub releases |",
        "| `common.py` | Shared library: hash computation, file resolution, platform config loading, emulator profiles |",
        "| `generate_readme.py` | Generate README.md and CONTRIBUTING.md from database |",
        "| `generate_site.py` | Generate all MkDocs site pages (this documentation) |",
        "| `deterministic_zip.py` | Rebuild MAME BIOS ZIPs deterministically (same ROMs = same hash) |",
        "| `crypto_verify.py` | 3DS RSA signature and AES crypto verification |",
        "| `sect233r1.py` | Pure Python ECDSA verification on sect233r1 curve (3DS OTP cert) |",
        "| `batch_profile.py` | Batch profiling automation for libretro cores |",
        "| `migrate.py` | Migrate flat bios structure to Manufacturer/Console/ hierarchy |",
        "",
        "## Large files",
        "",
        "Files over 50 MB are stored as assets on the `large-files` GitHub release.",
        "They are listed in `.gitignore` so they don't bloat the git repository.",
        "`generate_db.py` downloads them from the release when rebuilding the database,",
        "using `fetch_large_file()` from `common.py`. The same function is used by",
        "`generate_pack.py` when a file has a hash mismatch with the local variant.",
        "",
        "## Scrapers",
        "",
        "Located in `scripts/scraper/`. Each inherits `BaseScraper` and implements `fetch_requirements()`.",
        "",
        "| Scraper | Source | Format |",
        "|---------|--------|--------|",
        "| `libretro_scraper` | System.dat + core-info .info files | clrmamepro DAT |",
        "| `batocera_scraper` | batocera-systems script | Python dict |",
        "| `recalbox_scraper` | es_bios.xml | XML |",
        "| `retrobat_scraper` | batocera-systems.json | JSON |",
        "| `emudeck_scraper` | checkBIOS.sh | Bash + CSV |",
        "| `retrodeck_scraper` | component manifests | JSON per component |",
        "| `coreinfo_scraper` | .info files from libretro-core-info | INI-like |",
        "",
        "Internal modules: `base_scraper.py` (abstract base with `_fetch_raw()` caching",
        "and shared CLI), `dat_parser.py` (clrmamepro DAT format parser).",
        "",
        "Adding a scraper: inherit `BaseScraper`, implement `fetch_requirements()`,",
        "call `scraper_cli(YourScraper)` in `__main__`.",
        "",
    ]
    return "\n".join(lines) + "\n"


def generate_wiki_profiling() -> str:
    """Generate the emulator profiling methodology guide."""
    lines = [
        f"# Profiling guide - {SITE_NAME}",
        "",
        "How to create an emulator profile from source code.",
        "",
        "## Approach",
        "",
        "A profile documents what an emulator loads at runtime.",
        "The source code is the reference because it reflects actual behavior.",
        "Documentation, .info files, and wikis are useful starting points",
        "but are verified against the code.",
        "",
        "## Steps",
        "",
        "### 1. Find the source code",
        "",
        "Check these locations in order:",
        "",
        "1. Upstream original (the emulator's own repository)",
        "2. Libretro fork (may have adapted paths or added files)",
        "3. If not on GitHub: GitLab, Codeberg, SourceForge, archive.org",
        "",
        "Always clone both upstream and libretro port to compare.",
        "",
        "### 2. Trace file loading",
        "",
        "Read the code flow. Don't grep keywords by assumption.",
        "Each emulator has its own way of loading files.",
        "",
        "Look for:",
        "",
        "- `fopen`, `open`, `read_file`, `load_rom`, `load_bios` calls",
        "- `retro_system_directory` / `system_dir` in libretro cores",
        "- File existence checks (`path_is_valid`, `file_exists`)",
        "- Hash validation (MD5, CRC32, SHA1 comparisons in code)",
        "- Size validation (`fseek`/`ftell`, `stat`, fixed buffer sizes)",
        "",
        "### 3. Determine required vs optional",
        "",
        "This is decided by code behavior, not by judgment:",
        "",
        "- **required**: the core does not start or function without the file",
        "- **optional**: the core works with degraded functionality without it",
        "- **hle_fallback: true**: the core has a high-level emulation path when the file is missing",
        "",
        "### 4. Document divergences",
        "",
        "When the libretro port differs from the upstream:",
        "",
        "- `mode: libretro` - file only used by the libretro core",
        "- `mode: standalone` - file only used in standalone mode",
        "- `mode: both` - used by both (default, can be omitted)",
        "",
        "Path differences (current dir vs system_dir) are normal adaptation,",
        "not a divergence. Name changes (e.g. `naomi2_` to `n2_`) may be intentional",
        "to avoid conflicts in the shared system directory.",
        "",
        "### 5. Write the YAML profile",
        "",
        "```yaml",
        "emulator: Dolphin",
        "type: standalone + libretro",
        "core_classification: community_fork",
        "source: https://github.com/libretro/dolphin",
        "upstream: https://github.com/dolphin-emu/dolphin",
        "profiled_date: 2026-03-25",
        "core_version: 5.0-21264",
        "systems:",
        "  - nintendo-gamecube",
        "  - nintendo-wii",
        "",
        "files:",
        "  - name: GC/USA/IPL.bin",
        "    system: nintendo-gamecube",
        "    required: false",
        "    hle_fallback: true",
        "    size: 2097152",
        "    validation: [size, adler32]",
        "    known_hash_adler32: 0x4f1f6f5c",
        "    region: north-america",
        "    source_ref: Source/Core/Core/Boot/Boot_BS2Emu.cpp:42",
        "```",
        "",
        "### 6. Validate",
        "",
        "```bash",
        "python scripts/cross_reference.py --emulator dolphin --json",
        "python scripts/verify.py --emulator dolphin",
        "```",
        "",
        "## YAML field reference",
        "",
        "### Profile fields",
        "",
        "| Field | Required | Description |",
        "|-------|----------|-------------|",
        "| `emulator` | yes | display name |",
        "| `type` | yes | `libretro`, `standalone`, `standalone + libretro`, `alias`, `launcher` |",
        "| `core_classification` | no | `pure_libretro`, `official_port`, `community_fork`, `frozen_snapshot`, `enhanced_fork`, `game_engine`, `embedded_hle`, `alias`, `launcher` |",
        "| `source` | yes | libretro core repository URL |",
        "| `upstream` | no | original emulator repository URL |",
        "| `profiled_date` | yes | date of source analysis |",
        "| `core_version` | yes | version analyzed |",
        "| `systems` | yes | list of system IDs this core handles |",
        "| `cores` | no | list of core names (default: profile filename) |",
        "| `files` | yes | list of file entries |",
        "| `notes` | no | free-form technical notes |",
        "| `exclusion_note` | no | why the profile has no files |",
        "| `data_directories` | no | references to data dirs in `_data_dirs.yml` |",
        "",
        "### File entry fields",
        "",
        "| Field | Description |",
        "|-------|-------------|",
        "| `name` | filename as the core expects it |",
        "| `required` | true if the core needs this file to function |",
        "| `system` | system ID this file belongs to |",
        "| `size` | expected size in bytes |",
        "| `md5`, `sha1`, `crc32`, `sha256` | expected hashes from source code |",
        "| `validation` | list of checks the code performs: `size`, `crc32`, `md5`, `sha1` |",
        "| `aliases` | alternate filenames for the same file |",
        "| `mode` | `libretro`, `standalone`, or `both` |",
        "| `hle_fallback` | true if a high-level emulation path exists |",
        "| `category` | `bios` (default), `game_data`, `bios_zip` |",
        "| `region` | geographic region (e.g. `north-america`, `japan`) |",
        "| `source_ref` | source file and line number |",
        "| `path` | path relative to system directory |",
        "| `description` | what this file is |",
        "| `note` | additional context |",
        "| `archive` | parent ZIP if this file is inside an archive |",
        "| `contents` | structure of files inside a BIOS ZIP |",
        "| `storage` | `embedded` (default), `external`, `user_provided` |",
        "",
    ]
    return "\n".join(lines) + "\n"


def generate_wiki_data_model(db: dict, profiles: dict) -> str:
    """Generate data model documentation from actual database structure."""
    files_count = len(db.get("files", {}))
    by_md5 = len(db.get("indexes", {}).get("by_md5", {}))
    by_name = len(db.get("indexes", {}).get("by_name", {}))
    by_crc32 = len(db.get("indexes", {}).get("by_crc32", {}))
    by_path = len(db.get("indexes", {}).get("by_path_suffix", {}))

    lines = [
        f"# Data model - {SITE_NAME}",
        "",
        "## database.json",
        "",
        f"Primary key: SHA1. **{files_count}** file entries.",
        "",
        "Each entry:",
        "",
        "```json",
        '{',
        '  "path": "bios/Nintendo/GameCube/GC/USA/IPL.bin",',
        '  "name": "IPL.bin",',
        '  "size": 2097152,',
        '  "sha1": "...",',
        '  "md5": "...",',
        '  "sha256": "...",',
        '  "crc32": "...",',
        '  "adler32": "..."',
        '}',
        "```",
        "",
        "### Indexes",
        "",
        f"| Index | Entries | Purpose |",
        f"|-------|---------|---------|",
        f"| `by_md5` | {by_md5} | MD5 to SHA1 lookup (Batocera, Recalbox verification) |",
        f"| `by_name` | {by_name} | filename to SHA1 list (name-based resolution) |",
        f"| `by_crc32` | {by_crc32} | CRC32 to SHA1 lookup |",
        f"| `by_path_suffix` | {by_path} | relative path to SHA1 (regional variant disambiguation) |",
        "",
        "### File resolution order",
        "",
        "`resolve_local_file` tries these steps in order:",
        "",
        "1. Path suffix exact match (for regional variants with same filename)",
        "2. SHA1 exact match",
        "3. MD5 direct lookup (supports truncated Batocera 29-char MD5)",
        "4. Name + alias lookup without hash (existence mode)",
        "5. Name + alias with md5_composite / direct MD5 per candidate",
        "6. zippedFile content match via inner ROM MD5 index",
        "7. MAME clone fallback (deduped ZIP mapped to canonical name)",
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
        "## Emulator YAML",
        "",
        f"**{len(profiles)}** profiles. Source-verified from emulator code.",
        "",
        "See the [profiling guide](profiling.md) for the full field reference.",
        "",
    ]
    return "\n".join(lines) + "\n"


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


def _build_emulator_file_index(profiles: dict) -> dict[str, dict]:
    """Map emulator_name -> {files: set, systems: set} for cross-reference."""
    index = {}
    for name, profile in profiles.items():
        if profile.get("type") == "alias":
            continue
        index[name] = {
            "files": {f.get("name", "") for f in profile.get("files", [])},
            "systems": set(profile.get("systems", [])),
        }
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

    # Group emulators by classification for nav
    by_class: dict[str, list[tuple[str, str]]] = {}
    for name in sorted(unique_profiles.keys()):
        p = unique_profiles[name]
        cls = p.get("core_classification", "other")
        display = p.get("emulator", name)
        by_class.setdefault(cls, []).append((display, f"emulators/{name}.md"))

    # Classification display names
    cls_labels = {
        "pure_libretro": "Pure libretro",
        "official_port": "Official ports",
        "community_fork": "Community forks",
        "frozen_snapshot": "Frozen snapshots",
        "enhanced_fork": "Enhanced forks",
        "game_engine": "Game engines",
        "embedded_hle": "Embedded HLE",
        "launcher": "Launchers",
        "other": "Other",
    }

    emu_nav: list = [{"Overview": "emulators/index.md"}]
    for cls in ["official_port", "community_fork", "pure_libretro",
                "game_engine", "enhanced_fork", "frozen_snapshot",
                "embedded_hle", "launcher", "other"]:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        label = cls_labels.get(cls, cls)
        sub = [{display: path} for display, path in entries]
        emu_nav.append({f"{label} ({len(entries)})": sub})

    wiki_nav = [
        {"Overview": "wiki/index.md"},
        {"Architecture": "wiki/architecture.md"},
        {"Tools": "wiki/tools.md"},
        {"Profiling guide": "wiki/profiling.md"},
        {"Data model": "wiki/data-model.md"},
    ]

    return [
        {"Home": "index.md"},
        {"Platforms": platform_nav},
        {"Systems": system_nav},
        {"Emulators": emu_nav},
        {"Cross-reference": "cross-reference.md"},
        {"Gap Analysis": "gaps.md"},
        {"Wiki": wiki_nav},
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
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    unique_count = sum(1 for p in profiles.values() if p.get("type") != "alias")
    print(f"  {len(profiles)} profiles ({unique_count} unique, {len(profiles) - unique_count} aliases)")

    # Build cross-reference indexes
    platform_files = _build_platform_file_index(coverages)
    emulator_files = _build_emulator_file_index(profiles)

    # Generate home
    print("Generating home page...")
    (docs / "index.md").write_text(generate_home(db, coverages, profiles, registry))

    # Build system_id -> manufacturer page map (needed by all generators)
    print("Building system cross-reference map...")
    manufacturers = _group_by_manufacturer(db)
    _build_system_page_map_from_data(manufacturers, coverages, db)
    print(f"  {len(_system_page_map)} system IDs mapped to pages")

    # Generate platform pages
    print("Generating platform pages...")
    (docs / "platforms" / "index.md").write_text(generate_platform_index(coverages))
    for name, cov in coverages.items():
        (docs / "platforms" / f"{name}.md").write_text(generate_platform_page(name, cov, registry, emulator_files))

    # Generate system pages
    print("Generating system pages...")

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

    # Generate cross-reference page
    print("Generating cross-reference page...")
    (docs / "cross-reference.md").write_text(
        generate_cross_reference(coverages, profiles)
    )

    # Generate gap analysis page
    print("Generating gap analysis page...")
    (docs / "gaps.md").write_text(
        generate_gap_analysis(profiles, coverages, db)
    )

    # Wiki pages: copy manually maintained sources + generate dynamic ones
    print("Generating wiki pages...")
    wiki_dest = docs / "wiki"
    wiki_dest.mkdir(parents=True, exist_ok=True)
    wiki_src = Path(WIKI_SRC_DIR)
    if wiki_src.is_dir():
        for src_file in wiki_src.glob("*.md"):
            shutil.copy2(src_file, wiki_dest / src_file.name)
    # data-model.md is generated (contains live DB stats)
    (wiki_dest / "data-model.md").write_text(generate_wiki_data_model(db, profiles))

    # Generate contributing
    print("Generating contributing page...")
    (docs / "contributing.md").write_text(generate_contributing())

    # Update mkdocs.yml nav section only (avoid yaml.dump round-trip mangling quotes)
    print("Updating mkdocs.yml nav...")
    nav = generate_mkdocs_nav(coverages, manufacturers, profiles)
    nav_yaml = yaml.dump({"nav": nav}, default_flow_style=False, sort_keys=False, allow_unicode=True)

    # Rewrite mkdocs.yml entirely (static config + generated nav)
    mkdocs_static = """\
site_name: RetroBIOS
site_url: https://abdess.github.io/retrobios/
repo_url: https://github.com/Abdess/retrobios
repo_name: Abdess/retrobios
theme:
  name: material
  palette:
  - media: (prefers-color-scheme)
    toggle:
      icon: material/brightness-auto
      name: Switch to light mode
  - media: '(prefers-color-scheme: light)'
    scheme: default
    toggle:
      icon: material/brightness-7
      name: Switch to dark mode
  - media: '(prefers-color-scheme: dark)'
    scheme: slate
    toggle:
      icon: material/brightness-4
      name: Switch to auto
  font: false
  features:
  - navigation.tabs
  - navigation.sections
  - navigation.top
  - navigation.indexes
  - search.suggest
  - search.highlight
  - content.tabs.link
  - toc.follow
markdown_extensions:
- tables
- admonition
- attr_list
- md_in_html
- toc:
    permalink: true
- pymdownx.details
- pymdownx.superfences
- pymdownx.tabbed:
    alternate_style: true
plugins:
- search
"""
    with open("mkdocs.yml", "w") as f:
        f.write(mkdocs_static)
        f.write(nav_yaml)

    total_pages = (
        1  # home
        + 1 + len(coverages)  # platform index + detail
        + 1 + len(manufacturers)  # system index + detail
        + 1  # cross-reference
        + 1 + len(profiles)  # emulator index + detail
        + 1  # gap analysis
        + 5  # wiki (index, architecture, tools, profiling, data model)
        + 1  # contributing
    )
    print(f"\nGenerated {total_pages} pages in {args.docs_dir}/")


if __name__ == "__main__":
    main()
