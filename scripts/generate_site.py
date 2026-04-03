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
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    require_yaml,
    write_if_changed,
)

yaml = require_yaml()
from generate_readme import compute_coverage

DOCS_DIR = "docs"
SITE_NAME = "RetroBIOS"
REPO_URL = "https://github.com/Abdess/retrobios"
RELEASE_URL = f"{REPO_URL}/releases/latest"
GENERATED_DIRS = ["platforms", "systems", "emulators"]
WIKI_SRC_DIR = "wiki"  # manually maintained wiki sources
SYSTEM_ICON_BASE = "https://raw.githubusercontent.com/libretro/retroarch-assets/master/xmb/systematic/png"

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

# Global index: maps system_id -> (manufacturer_slug, console_name) for cross-linking
_system_page_map: dict[str, tuple[str, str]] = {}


def _build_system_page_map_from_data(
    manufacturers: dict,
    coverages: dict,
    db: dict,
) -> None:
    """Build system_id -> (manufacturer_slug, console_name) mapping.

    Uses platform file paths to trace system_id -> bios directory -> manufacturer page.
    """
    db.get("files", {})
    db.get("indexes", {}).get("by_name", {})

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


def _slugify_anchor(text: str) -> str:
    """Slugify text for MkDocs anchor compatibility."""
    import re

    slug = text.lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    slug = slug.strip("-")
    return slug


def _system_link(sys_id: str, prefix: str = "") -> str:
    """Generate a markdown link to a system page with anchor."""
    if sys_id in _system_page_map:
        slug, console = _system_page_map[sys_id]
        anchor = _slugify_anchor(console)
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
                        parts = [
                            f"{ik}: {iv}"
                            for ik, iv in item.items()
                            if not isinstance(iv, (dict, list))
                        ]
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
                parts = [
                    f"{ik}: {iv}"
                    for ik, iv in item.items()
                    if not isinstance(iv, (dict, list))
                ]
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


# Home page


def generate_home(
    db: dict, coverages: dict, profiles: dict, registry: dict | None = None
) -> str:
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    ts = _timestamp()

    unique = {
        k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")
    }
    emulator_count = len(unique)

    # Classification stats
    classifications: dict[str, int] = {}
    for p in unique.values():
        cls = p.get("core_classification", "other")
        if cls not in CLS_LABELS or cls == "unclassified":
            cls = "other"
        classifications[cls] = classifications.get(cls, 0) + 1

    # Count total systems across all profiles
    all_systems = set()
    for p in unique.values():
        all_systems.update(p.get("systems", []))

    lines = [
        '<div class="rb-hero" markdown>',
        "",
        f"# {SITE_NAME}",
        "",
        "Source-verified BIOS and firmware packs for retrogaming platforms.",
        "",
        "</div>",
        "",
        '<div class="rb-stats" markdown>',
        "",
        '<div class="rb-stat" markdown>',
        f'<span class="rb-stat-value">{total_files:,}</span>',
        '<span class="rb-stat-label">Files</span>',
        "</div>",
        "",
        '<div class="rb-stat" markdown>',
        f'<span class="rb-stat-value">{len(coverages)}</span>',
        '<span class="rb-stat-label">Platforms</span>',
        "</div>",
        "",
        '<div class="rb-stat" markdown>',
        f'<span class="rb-stat-value">{emulator_count}</span>',
        '<span class="rb-stat-label">Emulators profiled</span>',
        "</div>",
        "",
        '<div class="rb-stat" markdown>',
        f'<span class="rb-stat-value">{_fmt_size(total_size)}</span>',
        '<span class="rb-stat-label">Total size</span>',
        "</div>",
        "",
        "</div>",
        "",
    ]

    # Platforms FIRST (main action)
    lines.extend(
        [
            "## Platforms",
            "",
            "| | Platform | Files | Verification | Download |",
            "|---|----------|-------|-------------|----------|",
        ]
    )

    mode_icons = {"md5": "MD5", "sha1": "SHA1", "existence": "exists"}

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        logo_url = (registry or {}).get(name, {}).get("logo", "")
        logo_md = (
            f"![{display}]({logo_url}){{ width=20 loading=lazy }}" if logo_url else ""
        )
        mode_label = mode_icons.get(cov["mode"], cov["mode"])

        lines.append(
            f"| {logo_md} | [{display}](platforms/{name}.md) | "
            f"{cov['present']:,} | {mode_label} | "
            f"[Pack]({RELEASE_URL}){{ .md-button .md-button--primary }} |"
        )

    # Quick start (collapsible -- secondary info)
    lines.extend(
        [
            "",
            '??? info "Where to extract"',
            "",
            "    | Platform | Extract to |",
            "    |----------|-----------|",
            "    | RetroArch / Lakka | `system/` |",
            "    | Batocera | `/userdata/bios/` |",
            "    | BizHawk | `Firmware/` |",
            "    | EmuDeck | `Emulation/bios/` |",
            "    | Recalbox | `/recalbox/share/bios/` |",
            "    | RetroBat | `bios/` |",
            "    | RetroDECK | `~/retrodeck/bios/` |",
            "    | RetroPie | `~/RetroPie/BIOS/` |",
            "    | RomM | `bios/{platform_slug}/` |",
            "",
        ]
    )

    # Emulator classification breakdown
    lines.extend(
        [
            "## Emulator profiles",
            "",
            "| Classification | Count |",
            "|---------------|-------|",
        ]
    )
    for cls, count in sorted(classifications.items(), key=lambda x: -x[1]):
        label = CLS_LABELS.get(cls, cls)
        lines.append(f"| [{label}](emulators/index.md#{cls}) | {count} |")

    # Methodology (collapsible)
    lines.extend(
        [
            "",
            '??? abstract "Methodology"',
            "",
            "    Each file is checked against the emulator's source code. "
            "Documentation and metadata can drift from actual runtime behavior, "
            "so the source is the primary reference.",
            "",
            "    1. **Upstream emulator source** -- what the original project "
            "loads (Dolphin, PCSX2, Mednafen...)",
            "    2. **Libretro core source** -- the RetroArch port, which may "
            "adapt paths or add files",
            "    3. **`.info` declarations** -- metadata that platforms rely on, "
            "checked for accuracy",
            "",
        ]
    )

    # Quick links
    lines.extend(
        [
            "---",
            "",
            "[Systems](systems/index.md){ .md-button } "
            "[Emulators](emulators/index.md){ .md-button } "
            "[Cross-reference](cross-reference.md){ .md-button } "
            "[Gap Analysis](gaps.md){ .md-button } "
            "[Contributing](contributing.md){ .md-button .md-button--primary }",
            "",
            f'<div class="rb-timestamp">Generated on {ts}.</div>',
        ]
    )

    return "\n".join(lines) + "\n"


# Platform pages


def generate_platform_index(coverages: dict) -> str:
    total_files = sum(c["total"] for c in coverages.values())
    total_present = sum(c["present"] for c in coverages.values())
    total_verified = sum(c["verified"] for c in coverages.values())

    lines = [
        f"# Platforms - {SITE_NAME}",
        "",
        f"{len(coverages)} supported platforms with "
        f"{total_present:,} verified files.",
        "",
        "| Platform | Files | Verification | Download |",
        "|----------|-------|-------------|----------|",
    ]

    mode_labels = {
        "md5": '<span class="rb-badge rb-badge-success">MD5</span>',
        "sha1": '<span class="rb-badge rb-badge-success">SHA1</span>',
        "existence": '<span class="rb-badge rb-badge-info">existence</span>',
    }

    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]

        mode_html = mode_labels.get(
            cov["mode"],
            f'<span class="rb-badge rb-badge-muted">{cov["mode"]}</span>',
        )

        lines.append(
            f"| [{display}]({name}.md) | "
            f"{cov['present']:,} | {mode_html} | "
            f"[Pack]({RELEASE_URL}){{ .md-button .md-button--primary }} |"
        )

    return "\n".join(lines) + "\n"


def generate_platform_page(
    name: str,
    cov: dict,
    registry: dict | None = None,
    emulator_files: dict | None = None,
) -> str:
    config = cov["config"]
    display = cov["platform"]
    mode = cov["mode"]
    pct = _pct(cov["present"], cov["total"])

    logo_url = (registry or {}).get(name, {}).get("logo", "")
    logo_md = (
        f"![{display}]({logo_url}){{ width=48 align=right }}\n\n" if logo_url else ""
    )

    homepage = config.get("homepage", "")
    version = config.get("version", "")
    hash_type = config.get("hash_type", "")
    base_dest = config.get("base_destination", "")

    pct_val = cov["present"] / cov["total"] * 100 if cov["total"] else 0
    coverage_badge = (
        "rb-badge-success"
        if pct_val >= 95
        else "rb-badge-warning"
        if pct_val >= 70
        else "rb-badge-danger"
    )
    mode_badge = (
        "rb-badge-success" if mode in ("md5", "sha1") else "rb-badge-info"
    )

    lines = [
        f"# {display} - {SITE_NAME}",
        "",
        logo_md,
    ]

    # Stat cards
    lines.extend(
        [
            '<div class="rb-stats" markdown>',
            "",
            '<div class="rb-stat" markdown>',
            f'<span class="rb-stat-value">{cov["present"]}/{cov["total"]}</span>',
            f'<span class="rb-stat-label">Coverage ({pct})</span>',
            "</div>",
            "",
            '<div class="rb-stat" markdown>',
            f'<span class="rb-stat-value">{cov["verified"]}</span>',
            '<span class="rb-stat-label">Verified</span>',
            "</div>",
            "",
            '<div class="rb-stat" markdown>',
            f'<span class="rb-stat-value">{cov["missing"]}</span>',
            '<span class="rb-stat-label">Missing</span>',
            "</div>",
            "",
            '<div class="rb-stat" markdown>',
            f'<span class="rb-stat-value">'
            f'<span class="rb-badge {mode_badge}">{mode}</span></span>',
            '<span class="rb-stat-label">Verification</span>',
            "</div>",
            "",
            "</div>",
            "",
            "| | |",
            "|---|---|",
        ]
    )
    if hash_type:
        lines.append(f"| Hash type | {hash_type} |")
    if version:
        lines.append(f"| Version | {version} |")
    if base_dest:
        lines.append(f"| BIOS path | `{base_dest}/` |")
    if homepage:
        lines.append(f"| Homepage | [{homepage}]({homepage}) |")
    contrib_list = (registry or {}).get(name, {}).get("contributed_by", [])
    if contrib_list:
        for cb in contrib_list:
            username = cb.get("username", "")
            contribution = cb.get("contribution", "")
            pr = cb.get("pr")
            pr_link = f" ([#{pr}]({REPO_URL}/pull/{pr}))" if pr else ""
            lines.append(
                f"| Contributed by | [@{username}](https://github.com/{username})"
                f" - {contribution}{pr_link} |"
            )
    lines.extend(
        [
            "",
            f"[Download {display} Pack]({RELEASE_URL})"
            "{ .md-button .md-button--primary }",
            "",
        ]
    )

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
    lines.extend(
        [
            "## Systems overview",
            "",
            "| System | Files | Status | Emulators |",
            "|--------|-------|--------|-----------|",
        ]
    )
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
        sys_emus = []
        if emulator_files:
            for emu_name, emu_data in emulator_files.items():
                if sys_id in emu_data.get("systems", set()):
                    sys_emus.append(emu_name)
        emu_str = ", ".join(sys_emus[:3])
        if len(sys_emus) > 3:
            emu_str += f" +{len(sys_emus) - 3}"
        anchor = sys_id.replace(" ", "-")
        lines.append(
            f"| [{sys_id}](#{anchor}) | {ok_count}/{total} | {status} | {emu_str} |"
        )
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
            lines.append(f'<a id="{anchor}"></a>')
            lines.append(f'??? note "{sys_id} ({ok_count}/{total} - {status_tag})"')
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


# System pages


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
    total_mfr = len(manufacturers)
    total_consoles = sum(len(c) for c in manufacturers.values())
    total_files = sum(
        len(files) for consoles in manufacturers.values() for files in consoles.values()
    )

    lines = [
        f"# Systems - {SITE_NAME}",
        "",
        f"{total_mfr} manufacturers, {total_consoles} consoles, "
        f"{total_files:,} files in the repository.",
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
    manufacturer.lower().replace(" ", "-")
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

            # Cross-reference
            plats = sorted(p for p, names in platform_files.items() if name in names)
            emus = sorted(
                e
                for e, data in emulator_files.items()
                if name in data.get("files", set())
            )

            # Truncated hashes for readability
            sha1_short = sha1_full[:12] if sha1_full != "unknown" else "-"
            md5_short = md5_full[:12] if md5_full != "unknown" else "-"

            lines.append('<div class="rb-sys-file" markdown>')
            lines.append("")
            lines.append(
                f'**`{name}`** '
                f'<span class="rb-badge rb-badge-muted">{size}</span>'
            )
            lines.append("")
            lines.append(
                f'- SHA1: <span class="rb-hash" '
                f'title="{sha1_full}">`{sha1_short}...`</span>'
            )
            lines.append(
                f'- MD5: <span class="rb-hash" '
                f'title="{md5_full}">`{md5_short}...`</span>'
            )
            if plats:
                plat_badges = " ".join(
                    f'<span class="rb-badge rb-badge-info">'
                    f"[{p}](../platforms/{p}.md)</span>"
                    for p in plats
                )
                lines.append(f"- Platforms: {plat_badges}")
            if emus:
                emu_links = [_emulator_link(e, "../") for e in emus]
                lines.append(f"- Emulators: {', '.join(emu_links)}")
            lines.append("")
            lines.append("</div>")
            lines.append("")

        if variant_files:
            lines.append(
                f'??? note "Variants ({len(variant_files)})"'
            )
            lines.append("")
            for v in sorted(variant_files, key=lambda x: x["name"]):
                vname = v["name"]
                vmd5 = v.get("md5", "unknown")
                vmd5_short = vmd5[:12] if vmd5 != "unknown" else "-"
                lines.append(
                    f'    - `{vname}` '
                    f'<span class="rb-hash" title="{vmd5}">'
                    f"MD5: {vmd5_short}...</span>"
                )
            lines.append("")

        lines.append("")

    lines.append(f'<div class="rb-timestamp">Generated on {_timestamp()}.</div>')
    return "\n".join(lines) + "\n"


# Emulator pages


def generate_emulators_index(profiles: dict) -> str:
    unique = {
        k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")
    }
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
        lines.append(f"| [{label}](#{cls}) | {len(entries)} | {desc} |")
    lines.append("")

    for cls in cls_order:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        label = CLS_LABELS.get(cls, cls)
        desc = cls_desc.get(cls, "")
        lines.extend(
            [
                f'## <span class="rb-cls-dot rb-dot-{cls}"></span>{label} {{ #{cls} }}',
                "",
                f"*{desc}* -- {len(entries)} profiles",
                "",
                "| Engine | Systems | Files |",
                "|--------|---------|-------|",
            ]
        )

        for name, p in entries:
            emu_name = p.get("emulator", name)
            systems = p.get("systems", [])
            files = p.get("files", [])
            sys_str = ", ".join(systems[:3])
            if len(systems) > 3:
                sys_str += f" +{len(systems) - 3}"
            file_count = len(files)
            file_str = str(file_count) if file_count else "-"
            lines.append(f"| [{emu_name}]({name}.md) | {sys_str} | {file_str} |")
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


def generate_emulator_page(
    name: str,
    profile: dict,
    db: dict,
    platform_files: dict | None = None,
    data_names: set[str] | None = None,
) -> str:
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
    source_raw = profile.get("source", "")
    source = str(source_raw) if not isinstance(source_raw, dict) else ""
    upstream_raw = profile.get("upstream", "")
    upstream = str(upstream_raw) if not isinstance(upstream_raw, dict) else ""
    version = profile.get("core_version", "unknown")
    profile.get("display_name", emu_name)
    profiled = profile.get("profiled_date", "unknown")
    systems = profile.get("systems", [])
    cores = profile.get("cores", [name])
    files = profile.get("files", [])
    notes_raw = profile.get("notes", profile.get("note", ""))
    notes = (
        str(notes_raw).strip() if notes_raw and not isinstance(notes_raw, dict) else ""
    )
    exclusion = profile.get("exclusion_note", "")
    data_dirs = profile.get("data_directories", [])

    lines = [
        f"# {emu_name} - {SITE_NAME}",
        "",
        '<div class="rb-meta-card" markdown>',
        "",
        "| | |",
        "|---|---|",
        f"| Type | {emu_type} |",
    ]
    if classification:
        cls_display = CLS_LABELS.get(classification, classification)
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
    elif upstream and upstream != source:
        if upstream.startswith("http"):
            lines.append(f"| Upstream | [{upstream}]({upstream}) |")
        else:
            lines.append(f"| Upstream | {upstream} |")
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
        ("verification", "Verification mode"),
        ("source_ref", "Source ref"),
        ("analysis_date", "Analysis date"),
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
    lines.append("</div>")
    lines.append("")

    # Platform-specific details (rich structured data)
    platform_details = profile.get("platform_details")
    if platform_details and isinstance(platform_details, dict):
        lines.extend(['???+ info "Platform details"', ""])
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
        lines.append(f'???+ abstract "{label}"')
        lines.append("")
        _render_yaml_value(lines, val, indent=4)
        lines.append("")

    # Notes
    if notes:
        indented = notes.replace("\n", "\n    ")
        lines.extend(['???+ note "Technical notes"', f"    {indented}", ""])

    if not files:
        lines.append("No BIOS or firmware files required.")
        if exclusion:
            lines.extend(
                [
                    "",
                    '!!! info "Why no files"',
                    f"    {exclusion}",
                ]
            )
    else:
        from cross_reference import _resolve_source

        by_name = db.get("indexes", {}).get("by_name", {})
        by_name_lower = {k.lower(): k for k in by_name}
        by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})
        by_md5 = db.get("indexes", {}).get("by_md5", {})
        db_files = db.get("files", {})

        def _file_available(f: dict) -> bool:
            """Check if a file is available using the same resolution as cross_reference."""
            fname = f.get("name", "")
            if not fname:
                return False
            storage = f.get("storage", "")
            if storage in ("release", "large_file"):
                return True
            src = _resolve_source(
                fname, by_name, by_name_lower, data_names, by_path_suffix,
            )
            if src is not None:
                return True
            path_field = f.get("path", "")
            if path_field and path_field != fname:
                src = _resolve_source(
                    path_field, by_name, by_name_lower, data_names,
                    by_path_suffix,
                )
                if src is not None:
                    return True
            md5_raw = f.get("md5", "")
            if md5_raw:
                for md5_val in md5_raw.split(","):
                    md5_val = md5_val.strip().lower()
                    if md5_val and by_md5.get(md5_val):
                        return True
            sha1 = f.get("sha1", "")
            if sha1 and sha1 in db_files:
                return True
            return False

        # Stats by category
        bios_files = [f for f in files if f.get("category", "bios") == "bios"]
        game_data = [f for f in files if f.get("category") == "game_data"]
        bios_zips = [f for f in files if f.get("category") == "bios_zip"]

        in_repo_count = sum(1 for f in files if _file_available(f))
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
            in_repo = _file_available(f)
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

            # Status badges (HTML)
            badges = []
            if required:
                badges.append(
                    '<span class="rb-badge rb-badge-danger">required</span>'
                )
            else:
                badges.append(
                    '<span class="rb-badge rb-badge-muted">optional</span>'
                )
            if not in_repo:
                badges.append(
                    '<span class="rb-badge rb-badge-warning">missing</span>'
                )
            elif in_repo:
                badges.append(
                    '<span class="rb-badge rb-badge-success">in repo</span>'
                )
            if hle:
                badges.append(
                    '<span class="rb-badge rb-badge-info">HLE fallback</span>'
                )
            if mode:
                badges.append(
                    f'<span class="rb-badge rb-badge-muted">{mode}</span>'
                )
            if category and category != "bios":
                badges.append(
                    f'<span class="rb-badge rb-badge-info">{category}</span>'
                )
            if region:
                region_str = (
                    ", ".join(region) if isinstance(region, list) else str(region)
                )
                badges.append(
                    f'<span class="rb-badge rb-badge-muted">{region_str}</span>'
                )
            if storage and storage != "embedded":
                badges.append(
                    f'<span class="rb-badge rb-badge-muted">{storage}</span>'
                )
            if bundled:
                badges.append(
                    '<span class="rb-badge rb-badge-muted">bundled</span>'
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
                    f'<span class="rb-badge rb-badge-muted">in {archive}</span>'
                )
            if ftype and ftype != "bios":
                badges.append(
                    f'<span class="rb-badge rb-badge-muted">{ftype}</span>'
                )

            badge_str = " ".join(badges)
            border_cls = (
                "rb-file-entry-required" if required else "rb-file-entry-optional"
            )
            lines.append(
                f'<div class="rb-file-entry {border_cls}" markdown>'
            )
            lines.append("")
            lines.append(f"**`{fname}`** {badge_str}")
            if desc:
                lines.append(f"<br>{desc}")
            lines.append("")

            details = []
            if fpath and fpath != fname:
                details.append(f"Path: `{fpath}`")
            if fsystem:
                details.append(f"System: {_system_link(fsystem, '../')}")
            if size:
                if isinstance(size, list):
                    size_str = " / ".join(_fmt_size(s) for s in size)
                else:
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
                s = fsha1[:12]
                details.append(
                    f'SHA1: <span class="rb-hash" title="{fsha1}">'
                    f"`{s}...`</span>"
                )
            if fmd5:
                s = fmd5[:12]
                details.append(
                    f'MD5: <span class="rb-hash" title="{fmd5}">'
                    f"`{s}...`</span>"
                )
            if fcrc32:
                details.append(f"CRC32: `{fcrc32}`")
            if fsha256:
                s = fsha256[:12]
                details.append(
                    f'SHA256: <span class="rb-hash" title="{fsha256}">'
                    f"`{s}...`</span>"
                )
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
                plats = sorted(
                    p for p, names in platform_files.items() if fname in names
                )
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
                details.append(
                    f"Size options: {', '.join(_fmt_size(s) for s in size_options)}"
                )
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
            lines.append("</div>")
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


# Contributing page


def generate_gap_analysis(
    profiles: dict,
    coverages: dict,
    db: dict,
    data_names: set[str] | None = None,
) -> str:
    """Generate a unified gap analysis page.

    Combines verification results (from coverages/verify.py) with source
    provenance (from cross_reference) into a single truth dashboard.

    Sections:
    1. Verification status -- aggregated across all platforms
    2. Problem files -- missing, untested, hash mismatch
    3. Core complement -- emulator files not declared by any platform
    """
    from cross_reference import cross_reference as run_cross_reference

    from common import resolve_platform_cores

    # ---- Section 1: aggregate verify results across all platforms ----

    total_verified = 0
    total_untested = 0
    total_missing_verify = 0
    total_files_verify = 0

    platform_problems: list[dict] = []
    for pname, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        total_verified += cov["verified"]
        total_untested += cov["untested"]
        total_missing_verify += cov["missing"]
        total_files_verify += cov["total"]

        for d in cov["details"]:
            if d["status"] != "ok" or d.get("discrepancy"):
                platform_problems.append({
                    "platform": cov["platform"],
                    "platform_key": pname,
                    "name": d["name"],
                    "status": d["status"],
                    "required": d.get("required", True),
                    "reason": d.get("reason", ""),
                    "discrepancy": d.get("discrepancy", ""),
                    "system": d.get("system", ""),
                })

    pct_verified = (
        f"{total_verified / total_files_verify * 100:.0f}%"
        if total_files_verify
        else "0%"
    )

    lines = [
        f"# Gap Analysis - {SITE_NAME}",
        "",
        "Unified view of BIOS verification, file provenance, and coverage gaps.",
        "",
        '<div class="rb-stats" markdown>',
        "",
        '<div class="rb-stat" markdown>',
        f'<span class="rb-stat-value">{total_files_verify:,}</span>',
        '<span class="rb-stat-label">Total files (all platforms)</span>',
        "</div>",
        "",
        '<div class="rb-stat" markdown>',
        f'<span class="rb-stat-value">{total_verified:,}</span>',
        f'<span class="rb-stat-label">Verified ({pct_verified})</span>',
        "</div>",
        "",
        '<div class="rb-stat" markdown>',
        f'<span class="rb-stat-value">{total_untested:,}</span>',
        '<span class="rb-stat-label">Untested</span>',
        "</div>",
        "",
        '<div class="rb-stat" markdown>',
        f'<span class="rb-stat-value">{total_missing_verify:,}</span>',
        '<span class="rb-stat-label">Missing</span>',
        "</div>",
        "",
        "</div>",
        "",
    ]

    # ---- Verification per platform ----

    lines.extend([
        "## Verification by Platform",
        "",
        "| Platform | Files | Verified | Untested | Missing | Mode |",
        "|----------|------:|---------:|---------:|--------:|------|",
    ])

    for pname, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        m = cov["missing"]
        u = cov["untested"]
        missing_str = (
            f'<span class="rb-badge rb-badge-danger">{m}</span>'
            if m > 0
            else '<span class="rb-badge rb-badge-success">0</span>'
        )
        untested_str = (
            f'<span class="rb-badge rb-badge-warning">{u}</span>'
            if u > 0
            else str(u)
        )
        lines.append(
            f"| [{display}](platforms/{pname}.md) "
            f"| {cov['total']} "
            f"| {cov['verified']} "
            f"| {untested_str} "
            f"| {missing_str} "
            f"| {cov['mode']} |"
        )
    lines.append("")

    # ---- Section 2: Problem files ----

    missing_files: dict[str, dict] = {}
    untested_files: dict[str, dict] = {}
    mismatch_files: dict[str, dict] = {}

    for p in platform_problems:
        fname = p["name"]
        if p["status"] == "missing":
            entry = missing_files.setdefault(fname, {
                "name": fname, "required": p["required"],
                "platforms": [], "reason": p["reason"],
            })
            entry["platforms"].append(p["platform"])
            if p["required"]:
                entry["required"] = True
        elif p["status"] == "untested":
            entry = untested_files.setdefault(fname, {
                "name": fname, "required": p["required"],
                "platforms": [], "reason": p["reason"],
            })
            entry["platforms"].append(p["platform"])
        if p.get("discrepancy"):
            entry = mismatch_files.setdefault(fname, {
                "name": fname, "platforms": [],
                "discrepancy": p["discrepancy"],
            })
            entry["platforms"].append(p["platform"])

    total_problems = len(missing_files) + len(untested_files) + len(mismatch_files)

    if total_problems > 0:
        lines.extend([
            "## Problem Files",
            "",
            f"{len(missing_files)} missing, {len(untested_files)} untested, "
            f"{len(mismatch_files)} hash mismatch.",
            "",
        ])

        if missing_files:
            lines.extend([
                f'### Missing <span class="rb-badge rb-badge-danger">'
                f"{len(missing_files)} files</span>",
                "",
                "| File | Required | Platforms |",
                "|------|----------|-----------|",
            ])
            for fname in sorted(missing_files):
                f = missing_files[fname]
                req = "yes" if f["required"] else "no"
                plats = ", ".join(sorted(set(f["platforms"])))
                lines.append(f"| `{fname}` | {req} | {plats} |")
            lines.append("")

        if untested_files:
            lines.extend([
                f'### Untested <span class="rb-badge rb-badge-warning">'
                f"{len(untested_files)} files</span>",
                "",
                "Present but hash not verified.",
                "",
                "| File | Platforms | Reason |",
                "|------|----------|--------|",
            ])
            for fname in sorted(untested_files):
                f = untested_files[fname]
                plats = ", ".join(sorted(set(f["platforms"])))
                lines.append(f"| `{fname}` | {plats} | {f['reason']} |")
            lines.append("")

        if mismatch_files:
            lines.extend([
                f'### Hash Mismatch <span class="rb-badge rb-badge-warning">'
                f"{len(mismatch_files)} files</span>",
                "",
                "Platform says OK but emulator validation disagrees.",
                "",
                "| File | Platforms | Discrepancy |",
                "|------|----------|-------------|",
            ])
            for fname in sorted(mismatch_files):
                f = mismatch_files[fname]
                plats = ", ".join(sorted(set(f["platforms"])))
                lines.append(f"| `{fname}` | {plats} | {f['discrepancy']} |")
            lines.append("")

    # ---- Section 3: Core complement (cross-reference provenance) ----

    from common import expand_platform_declared_names

    all_declared: set[str] = set()
    declared: dict[str, set[str]] = {}
    for _name, cov in coverages.items():
        config = cov["config"]
        # Enrich with alias resolution (MD5 -> SHA1 -> canonical name + aliases)
        all_declared.update(expand_platform_declared_names(config, db))
        for sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                fname = fe.get("name", "")
                if fname:
                    declared.setdefault(sys_id, set()).add(fname)

    # Only include profiles relevant to at least one platform
    unique_profiles = {
        k: v
        for k, v in profiles.items()
        if v.get("type") not in ("alias", "test")
    }
    relevant_set: set[str] = set()
    for _name, cov in coverages.items():
        matched = resolve_platform_cores(cov["config"], unique_profiles)
        relevant_set.update(matched)
    active_profiles = {
        k: v for k, v in unique_profiles.items() if k in relevant_set
    }

    report = run_cross_reference(
        active_profiles, declared, db,
        data_names=data_names, all_declared=all_declared,
    )

    src_totals: dict[str, int] = {"bios": 0, "data": 0, "large_file": 0, "missing": 0}
    total_undeclared = 0
    emulator_gaps = []

    for emu_name, data in sorted(report.items()):
        if data["gaps"] == 0:
            continue
        total_undeclared += data["gaps"]
        for key in src_totals:
            src_totals[key] += data.get(f"gap_{key}", 0)
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
            "## Core Complement",
            "",
            f"Files loaded by emulators but not declared by any platform. "
            f"{total_undeclared:,} files across {len(emulator_gaps)} emulators, "
            f"{total_available:,} available ({pct_available}), "
            f"{src_totals['missing']} to source.",
            "",
            "### Provenance",
            "",
            "| Source | Count | Description |",
            "|--------|------:|-------------|",
            f"| bios/ | {src_totals['bios']} | In repository (database.json) |",
            f"| data/ | {src_totals['data']} | Data directories (buildbot, GitHub) |",
            f"| release | {src_totals['large_file']} "
            "| GitHub release assets (large files) |",
            f"| missing | {src_totals['missing']} | Not available, needs sourcing |",
            "",
            "### Per Emulator",
            "",
            "| Emulator | Undeclared | bios | data | release | Missing |",
            "|----------|----------:|-----:|-----:|--------:|--------:|",
        ])

        for emu_name, data in sorted(emulator_gaps, key=lambda x: -x[1]["gaps"]):
            display = data["emulator"]
            m = data.get("gap_missing", 0)
            missing_str = (
                f'<span class="rb-badge rb-badge-danger">{m}</span>'
                if m > 0
                else '<span class="rb-badge rb-badge-success">0</span>'
            )
            lines.append(
                f"| [{display}](emulators/{emu_name}.md) "
                f"| {data['gaps']} "
                f"| {data.get('gap_bios', 0)} "
                f"| {data.get('gap_data', 0)} "
                f"| {data.get('gap_large_file', 0)} "
                f"| {missing_str} |"
            )
        lines.append("")

        # List truly missing files with platform impact
        emu_to_platforms: dict[str, set[str]] = {}
        unique_profiles = {
            k: v
            for k, v in profiles.items()
            if v.get("type") not in ("alias", "test")
        }
        for pname in coverages:
            config = coverages[pname]["config"]
            matched = resolve_platform_cores(config, unique_profiles)
            for emu_name in matched:
                emu_to_platforms.setdefault(emu_name, set()).add(pname)

        all_src_missing: set[str] = set()
        src_missing_details: list[dict] = []
        for emu_name, data in emulator_gaps:
            for g in data["gap_details"]:
                if g["source"] == "missing" and g["name"] not in all_src_missing:
                    all_src_missing.add(g["name"])
                    src_missing_details.append({
                        "name": g["name"],
                        "emulator": data["emulator"],
                        "emu_key": emu_name,
                        "required": g["required"],
                        "source_ref": g["source_ref"],
                    })

        if src_missing_details:
            req_src = [m for m in src_missing_details if m["required"]]
            lines.extend([
                f"### Files to Source ({len(src_missing_details)} unique, "
                f"{len(req_src)} required)",
                "",
                "| File | Emulator | Required | Affects platforms | Source ref |",
                "|------|----------|----------|------------------|-----------|",
            ])
            for m in sorted(
                src_missing_details,
                key=lambda x: (not x["required"], x["name"]),
            ):
                plats = sorted(emu_to_platforms.get(m["emu_key"], set()))
                plat_badges = (
                    " ".join(
                        f'<span class="rb-badge rb-badge-info">{p}</span>'
                        for p in plats
                    )
                    if plats
                    else "-"
                )
                req = "yes" if m["required"] else "no"
                lines.append(
                    f"| `{m['name']}` | {m['emulator']} | {req} | "
                    f"{plat_badges} | {m['source_ref']} |"
                )
            lines.append("")

    # ---- Section 4: Acknowledged gaps (unsourceable files) ----

    all_unsourceable: list[dict] = []
    for emu_name, data in sorted(report.items()):
        for u in data.get("unsourceable", []):
            all_unsourceable.append({
                "name": u["name"],
                "emulator": data["emulator"],
                "reason": u["reason"],
                "source_ref": u.get("source_ref", ""),
            })

    if all_unsourceable:
        lines.extend([
            "## Acknowledged Gaps",
            "",
            f"{len(all_unsourceable)} files documented as unsourceable "
            "(verified from source code).",
            "",
            "| File | Emulator | Reason | Source ref |",
            "|------|----------|--------|-----------|",
        ])
        for u in sorted(all_unsourceable, key=lambda x: x["name"]):
            lines.append(
                f"| `{u['name']}` | {u['emulator']} | {u['reason']} "
                f"| {u['source_ref']} |"
            )
        lines.append("")

    lines.extend(["", f'<div class="rb-timestamp">Generated on {_timestamp()}.</div>'])
    return "\n".join(lines) + "\n"




def generate_cross_reference(
    coverages: dict,
    profiles: dict,
) -> str:
    """Generate cross-reference: Platform -> Core -> Systems -> Upstream."""
    unique = {
        k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")
    }

    # Build core -> profile lookup by core name
    core_to_profile: dict[str, str] = {}
    for pname, p in unique.items():
        for core in p.get("cores", [pname]):
            core_to_profile[str(core)] = pname

    total_cores = len(unique)
    total_upstreams = len({
        p.get("upstream", p.get("source", ""))
        for p in unique.values()
        if p.get("upstream") or p.get("source")
    })

    lines = [
        f"# Cross-reference - {SITE_NAME}",
        "",
        f"Platform > Core > Systems > Upstream emulator. "
        f"{total_cores} cores across {len(coverages)} platforms, "
        f"tracing back to {total_upstreams} upstream projects.",
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

        lines.append(f'??? abstract "[{display}](platforms/{pname}.md)"')
        lines.append("")

        # Resolve which profiles this platform uses
        if platform_cores == "all_libretro":
            matched = {
                k: v for k, v in unique.items() if "libretro" in v.get("type", "")
            }
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
            matched = {
                k: v for k, v in unique.items() if set(v.get("systems", [])) & psystems
            }

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
            cls_raw = p.get("core_classification", "-")
            cls = CLS_LABELS.get(cls_raw, cls_raw)
            p.get("type", "")
            upstream_raw2 = p.get("upstream", "")
            upstream = str(upstream_raw2) if not isinstance(upstream_raw2, dict) else ""
            source_raw2 = p.get("source", "")
            source = str(source_raw2) if not isinstance(source_raw2, dict) else ""
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
            if upstream and upstream.startswith("http"):
                upstream_short = upstream.replace("https://github.com/", "")
                upstream_display = f"[{upstream_short}]({upstream})"
            elif upstream:
                upstream_display = upstream
            elif source and source.startswith("http"):
                source_short = source.replace("https://github.com/", "")
                upstream_display = f"[{source_short}]({source})"
            elif source:
                upstream_display = source

            lines.append(
                f"    | [{emu_display}](emulators/{emu_name}.md) | {cls} | "
                f"{sys_str} | {file_str} | {upstream_display} |"
            )

        lines.append("")

    # Reverse view: by upstream emulator
    lines.extend(
        [
            "## By upstream emulator",
            "",
            "| Upstream | Cores | Classification | Platforms |",
            "|----------|-------|---------------|-----------|",
        ]
    )

    # Group profiles by upstream
    by_upstream: dict[str, list[str]] = {}
    for emu_name, p in sorted(unique.items()):
        raw_up = p.get("upstream", p.get("source", ""))
        up_str = str(raw_up) if not isinstance(raw_up, dict) else ""
        if up_str:
            by_upstream.setdefault(up_str, []).append(emu_name)

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
            raw_cls = unique[c].get("core_classification", "-")
            classifications.add(CLS_LABELS.get(raw_cls, raw_cls))
            all_plats.update(platform_membership.get(c, set()))

        cls_str = ", ".join(sorted(classifications))
        plat_str = ", ".join(sorted(all_plats)) if all_plats else "-"
        core_links = ", ".join(f"[{c}](emulators/{c}.md)" for c in sorted(cores))

        if upstream_url.startswith("http"):
            upstream_cell = f"[{upstream_short}]({upstream_url})"
        else:
            upstream_cell = upstream_short
        lines.append(
            f"| {upstream_cell} | {core_links} | "
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
        "{",
        '  "path": "bios/Nintendo/GameCube/GC/USA/IPL.bin",',
        '  "name": "IPL.bin",',
        '  "size": 2097152,',
        '  "sha1": "...",',
        '  "md5": "...",',
        '  "sha256": "...",',
        '  "crc32": "...",',
        '  "adler32": "..."',
        "}",
        "```",
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
        "`resolve_local_file` tries these steps in order:",
        "",
        "1. Path suffix exact match (for regional variants with same filename)",
        "2. SHA1 exact match",
        "3. MD5 direct lookup (supports truncated Batocera 29-char MD5)",
        "4. Name + alias lookup without hash (existence mode)",
        "5. Name + alias with md5_composite / direct MD5 per candidate",
        "6. zippedFile content match via inner ROM MD5 index",
        "7. MAME clone fallback (deduped ZIP mapped to canonical name)",
        "8. Data directory scan (exact path then case-insensitive basename walk)",
        "9. Agnostic fallback (size-constrained match under system path prefix)",
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


# Build cross-reference indexes


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


# mkdocs.yml nav generator


def generate_which_pack() -> str:
    """Generate the 'Which pack?' decision page."""
    rel = "https://github.com/Abdess/retrobios/releases"
    return f"""\
# Getting started

Some retro consoles need firmware files (commonly called BIOS) to run games.
Without them, the emulator either refuses to start the game or runs it with
reduced accuracy. This project collects and verifies those files so they are
ready to use.

## Quick install

The installer detects the platform, finds the BIOS folder, downloads what
is missing, and copies keys to standalone emulators (Yuzu, Eden, Ryujinx,
DuckStation, PCSX2, Dolphin, etc.) when they are present on the system.

**Linux / Mac / Steam Deck:**

```sh
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh
```

**Windows (PowerShell):**

```powershell
iwr -useb https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1 | iex
```

Nothing else needed. The installer handles everything.

---

## Manual download

Pick the pack that matches the setup from the [releases page]({rel}),
download it, and extract the files into the BIOS folder listed below.
After extraction, launch a game. If it needed BIOS, it will find it.

### Steam Deck

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| [EmuDeck](https://www.emudeck.com/) | Installs and configures multiple emulators, adds each game to the Steam library | [EmuDeck]({rel}) | `~/Emulation/bios/` |
| [RetroDECK](https://retrodeck.net/) | Single Flatpak app, all emulators bundled, one-click install from Discover | [RetroDECK]({rel}) | `~/retrodeck/` |
| RetroArch standalone | Installed from Discover, Steam, or Flatpak | [RetroArch]({rel}) | Open RetroArch > Settings > Directory > System, that is the folder |

### Windows

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| [RetroArch](https://www.retroarch.com/) | Multi-system emulator, loads different cores for each console | [RetroArch]({rel}) | The `system` folder next to `retroarch.exe` |
| [RetroBat](https://www.retrobat.org/) | Windows frontend with EmulationStation, includes RetroArch and standalone emulators | [RetroBat]({rel}) | The `bios` folder inside the RetroBat installation |
| [BizHawk](https://tasvideos.org/BizHawk) | Accuracy-focused multi-system emulator, popular for speedruns and TAS | [BizHawk]({rel}) | The `Firmware` folder inside the BizHawk installation |
| [LaunchBox](https://www.launchbox-app.com/) | Game library manager and launcher, uses RetroArch or standalone emulators behind the scenes | [RetroArch]({rel}) | Open RetroArch (via LaunchBox) > Settings > Directory > System |

### Linux

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| RetroArch (native) | Installed via package manager or AppImage | [RetroArch]({rel}) | `~/.config/retroarch/system/` |
| RetroArch (Flatpak) | Installed from Flathub | [RetroArch]({rel}) | `~/.var/app/org.libretro.RetroArch/config/retroarch/system/` |
| [Batocera](https://batocera.org/) | Bootable OS dedicated to gaming, runs from USB or full install, supports PC and SBC | [Batocera]({rel}) | `/userdata/bios/` |
| [Recalbox](https://www.recalbox.com/) | Bootable OS for retro gaming, streamlined interface, auto-configured | [Recalbox]({rel}) | `/recalbox/share/bios/` |

### macOS

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| [RetroArch](https://www.retroarch.com/) | Multi-system emulator | [RetroArch]({rel}) | `~/Library/Application Support/RetroArch/system/` |

### Raspberry Pi and single-board computers

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| [RetroPie](https://retropie.org.uk/) | The classic Pi emulation setup, largest community, most online guides | [RetroArch]({rel}) | `~/RetroPie/BIOS/` |
| [Lakka](https://www.lakka.tv/) | Lightweight RetroArch OS, minimal config, boots straight into the UI | [RetroArch]({rel}) | `/storage/system/` |
| [Batocera](https://batocera.org/) | Easy setup, works on Pi 3/4/5 and many other boards (Odroid, etc.) | [Batocera]({rel}) | `/userdata/bios/` |
| [Recalbox](https://www.recalbox.com/) | Plug-and-play experience, good for a first build | [Recalbox]({rel}) | `/recalbox/share/bios/` |

### Android handheld (Retroid Pocket, R36S, Miyoo, etc.)

Most Android handhelds run RetroArch. Download the [RetroArch pack]({rel})
and extract into `RetroArch/system/` on internal storage or SD card.

### Self-hosted ROM manager

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| [RomM](https://github.com/rommapp/romm) | Web-based ROM manager, plays games in the browser via EmulatorJS | [RomM]({rel}) | The `bios` folder in the RomM library, one subfolder per system |

---

## Full pack or Platform pack?

Each platform has two pack types on the [releases page]({rel}).

**Full pack** (recommended)

Contains the platform's own BIOS list plus all files needed by each
emulator core available on that platform. This covers alternate cores,
optional firmware that improves accuracy, and edge cases. Larger download,
but everything works out of the box with any core.

**Platform pack**

Contains only the files the platform officially checks for. Much smaller
download. Good for limited storage (SD cards, handhelds) or setups that
only use default cores.

When in doubt, take the full pack.

---

## After extraction

Launch a game. If it needed a BIOS file, the emulator will find it
automatically. No configuration needed.

If a game still asks for a missing file, check the
[platforms section](platforms/index.md) for the full file list, or the
[emulators section](emulators/index.md) for what each core expects.
"""


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

    unique_profiles = {
        k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")
    }

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
    for cls in [
        "official_port",
        "community_fork",
        "pure_libretro",
        "game_engine",
        "enhanced_fork",
        "frozen_snapshot",
        "embedded_hle",
        "launcher",
        "other",
    ]:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        label = cls_labels.get(cls, cls)
        sub = [{display: path} for display, path in entries]
        emu_nav.append({f"{label} ({len(entries)})": sub})

    wiki_nav = [
        {"Overview": "wiki/index.md"},
        {"Getting started": "wiki/getting-started.md"},
        {"FAQ": "wiki/faq.md"},
        {"Troubleshooting": "wiki/troubleshooting.md"},
        {"Architecture": "wiki/architecture.md"},
        {"Tools": "wiki/tools.md"},
        {"Advanced usage": "wiki/advanced-usage.md"},
        {"Verification modes": "wiki/verification-modes.md"},
        {"Data model": "wiki/data-model.md"},
        {"Profiling guide": "wiki/profiling.md"},
        {"Adding a platform": "wiki/adding-a-platform.md"},
        {"Adding a scraper": "wiki/adding-a-scraper.md"},
        {"Testing guide": "wiki/testing-guide.md"},
        {"Release process": "wiki/release-process.md"},
        {"Community tools": "wiki/community-tools.md"},
    ]

    return [
        {"Home": "index.md"},
        {"Download": "which-pack.md"},
        {"Platforms": platform_nav},
        {"Systems": system_nav},
        {"Emulators": emu_nav},
        {"Cross-reference": "cross-reference.md"},
        {"Gap Analysis": "gaps.md"},
        {"Wiki": wiki_nav},
        {"Contributing": "contributing.md"},
    ]


# Main


def main():
    parser = argparse.ArgumentParser(
        description="Generate MkDocs site from project data"
    )
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

    # Copy stylesheet if source exists
    css_src = Path("docs_assets") / "extra.css"
    css_dest = docs / "stylesheets" / "extra.css"
    if css_src.exists():
        css_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(css_src, css_dest)

    # Copy branding assets
    images_dest = docs / "assets" / "images"
    images_dest.mkdir(parents=True, exist_ok=True)
    assets_src = Path(".github") / "assets"
    for name, dest_name in [("logo.png", "logo.png"), ("favicon.png", "favicon.png")]:
        src = assets_src / name
        if src.exists():
            shutil.copy2(src, images_dest / dest_name)

    registry_path = Path(args.platforms_dir) / "_registry.yml"
    registry = {}
    if registry_path.exists():
        with open(registry_path) as f:
            registry = (yaml.safe_load(f) or {}).get("platforms", {})

    platform_names = list_registered_platforms(
        args.platforms_dir, include_archived=True
    )

    from common import load_data_dir_registry
    from cross_reference import _build_supplemental_index

    data_registry = load_data_dir_registry(args.platforms_dir)
    suppl_names = _build_supplemental_index()

    print("Computing platform coverage...")
    coverages = {}
    for name in sorted(platform_names):
        try:
            cov = compute_coverage(
                name, args.platforms_dir, db, data_registry, suppl_names
            )
            coverages[name] = cov
            print(
                f"  {cov['platform']}: {cov['present']}/{cov['total']} ({_pct(cov['present'], cov['total'])})"
            )
        except FileNotFoundError as e:
            print(f"  {name}: skipped ({e})", file=sys.stderr)

    print("Loading emulator profiles...")
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    unique_count = sum(1 for p in profiles.values() if p.get("type") != "alias")
    print(
        f"  {len(profiles)} profiles ({unique_count} unique, {len(profiles) - unique_count} aliases)"
    )

    # Build cross-reference indexes
    platform_files = _build_platform_file_index(coverages)
    emulator_files = _build_emulator_file_index(profiles)

    # Generate home
    print("Generating home page...")
    write_if_changed(
        str(docs / "index.md"), generate_home(db, coverages, profiles, registry)
    )

    # Build system_id -> manufacturer page map (needed by all generators)
    print("Building system cross-reference map...")
    manufacturers = _group_by_manufacturer(db)
    _build_system_page_map_from_data(manufacturers, coverages, db)
    print(f"  {len(_system_page_map)} system IDs mapped to pages")

    # Generate platform pages
    print("Generating platform pages...")
    write_if_changed(
        str(docs / "platforms" / "index.md"), generate_platform_index(coverages)
    )
    for name, cov in coverages.items():
        write_if_changed(
            str(docs / "platforms" / f"{name}.md"),
            generate_platform_page(name, cov, registry, emulator_files),
        )

    # Generate system pages
    print("Generating system pages...")

    write_if_changed(
        str(docs / "systems" / "index.md"), generate_systems_index(manufacturers)
    )
    for mfr, consoles in manufacturers.items():
        slug = mfr.lower().replace(" ", "-")
        page = generate_system_page(mfr, consoles, platform_files, emulator_files)
        write_if_changed(str(docs / "systems" / f"{slug}.md"), page)

    # Generate emulator pages
    print("Generating emulator pages...")
    write_if_changed(
        str(docs / "emulators" / "index.md"), generate_emulators_index(profiles)
    )
    for name, profile in profiles.items():
        page = generate_emulator_page(name, profile, db, platform_files, suppl_names)
        write_if_changed(str(docs / "emulators" / f"{name}.md"), page)

    # Generate cross-reference page
    print("Generating cross-reference page...")
    write_if_changed(
        str(docs / "cross-reference.md"), generate_cross_reference(coverages, profiles)
    )

    # Generate gap analysis page
    print("Generating gap analysis page...")
    write_if_changed(
        str(docs / "gaps.md"),
        generate_gap_analysis(profiles, coverages, db, suppl_names),
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
    write_if_changed(
        str(wiki_dest / "data-model.md"), generate_wiki_data_model(db, profiles)
    )

    # Generate which-pack page
    print("Generating which-pack page...")
    write_if_changed(str(docs / "which-pack.md"), generate_which_pack())

    # Generate contributing
    print("Generating contributing page...")
    write_if_changed(str(docs / "contributing.md"), generate_contributing())

    # Update mkdocs.yml nav section only (avoid yaml.dump round-trip mangling quotes)
    print("Updating mkdocs.yml nav...")
    nav = generate_mkdocs_nav(coverages, manufacturers, profiles)
    nav_yaml = yaml.dump(
        {"nav": nav}, default_flow_style=False, sort_keys=False, allow_unicode=True
    )

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
  logo: assets/images/logo.png
  favicon: assets/images/favicon.png
  icon:
    logo: material/chip
  features:
  - navigation.tabs
  - navigation.sections
  - navigation.top
  - navigation.indexes
  - search.suggest
  - search.highlight
  - content.tabs.link
  - toc.follow
extra_css:
- stylesheets/extra.css
markdown_extensions:
- tables
- admonition
- attr_list
- md_in_html
- toc:
    permalink: true
- pymdownx.details
- pymdownx.superfences:
    custom_fences:
    - name: mermaid
      class: mermaid
      format: !!python/name:pymdownx.superfences.fence_code_format
- pymdownx.tabbed:
    alternate_style: true
plugins:
- search
"""
    write_if_changed("mkdocs.yml", mkdocs_static + nav_yaml)

    total_pages = (
        1  # home
        + 1
        + len(coverages)  # platform index + detail
        + 1
        + len(manufacturers)  # system index + detail
        + 1  # cross-reference
        + 1
        + len(profiles)  # emulator index + detail
        + 1  # gap analysis
        + 14  # wiki pages (copied from wiki/ + generated data-model)
        + 1  # contributing
    )
    print(f"\nGenerated {total_pages} pages in {args.docs_dir}/")


if __name__ == "__main__":
    main()
