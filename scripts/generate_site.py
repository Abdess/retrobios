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
import csv
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    compute_composition,
    GAME_DATA_TOPS,
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_provenance_snapshots,
    parse_md5_list,
    require_yaml,
    unique_emulator_profiles,
    write_if_changed,
    yaml_load,
)

yaml = require_yaml()
from generate_readme import compute_coverage, manifest_totals
from profile_sync import source_ref_values, split_source_ref
from provenance_report import build_report
import upstream

DOCS_DIR = "docs"
SITE_NAME = "RetroBIOS"
REPO_URL = "https://github.com/Abdess/retrobios"
RELEASE_URL = f"{REPO_URL}/releases/latest"
SITE_URL = "https://abdess.github.io/retrobios/"
GENERATED_DIRS = ["platforms", "systems", "emulators", "wiki", "api", "downloads"]
WIKI_SRC_DIR = "wiki"  # manually maintained wiki sources
SYSTEM_ICON_BASE = "https://raw.githubusercontent.com/libretro/retroarch-assets/master/xmb/systematic/png"
ICON_CACHE_PATH = Path(".cache") / "system_icons.json"

# Icon names confirmed to exist upstream. A name absent from this map has not
# been checked yet; a name mapped to False has no icon and gets none rendered,
# because a heading with a broken image reads worse than a heading without one.
_icon_available: dict[str, bool] = {}


def _by_mode(value, mode: str) -> str:
    """Read a profile field that may be keyed by build mode."""
    if isinstance(value, dict):
        return str(value.get(mode) or "") if mode else ""
    return str(value or "")


def _repo_pins(profile: dict, field: str, label: str) -> list[tuple[str, str, str]]:
    """Pair each declared repository URL with its own revision.

    A profile whose builds live in separate repositories keys both the URL
    and the revision by build mode. Reading them apart would pin a libretro
    fork to the standalone revision and produce a permalink into a tree that
    never held the cited line. Each tuple is (url, pin, source_commit
    fallback for that same mode).
    """
    raw = profile.get(field, "")
    pin_field = profile.get(f"{field}_commit") or ""
    source_field = profile.get("source_commit") or ""

    if not isinstance(raw, dict):
        if not raw:
            return []
        return [
            (
                str(raw),
                _by_mode(pin_field, label),
                _by_mode(source_field, label),
            )
        ]

    # The requested build mode first, so it wins when several repositories
    # would otherwise be equally good candidates.
    ordered = ([label] if label and label in raw else []) + [
        key for key in raw if key != label
    ]
    return [
        (str(raw[key]), _by_mode(pin_field, key), _by_mode(source_field, key))
        for key in ordered
        if raw.get(key)
    ]


def _forge_sources(profile: dict, label: str = "") -> list[tuple[upstream.Repo, str]]:
    """Supported source repositories and immutable revisions for a profile."""
    candidates: list[tuple[upstream.Repo, str]] = []
    seen: set[tuple[str, str, str]] = set()
    source_repos: set[tuple[str, str]] = set()

    for field in ("source", "upstream"):
        for value, pin, fallback in _repo_pins(profile, field, label):
            repo = upstream.parse_repo(value)
            if repo is None:
                continue
            repo_key = (repo.host, repo.slug)
            if field == "upstream" and not pin and repo_key in source_repos:
                pin = fallback
            if not pin:
                continue
            key = (repo.host, repo.slug, pin)
            if key not in seen:
                candidates.append((repo, pin))
                seen.add(key)
            if field == "source":
                source_repos.add(repo_key)
    return candidates


def _source_permalink(repo: upstream.Repo, pin: str, path: str,
                      start: int | None, end: int | None) -> str:
    """Forge-specific browser URL for one file at one immutable revision."""
    quoted_path = urllib.parse.quote(path, safe="/@:+-._~")
    base = f"https://{repo.host}/{repo.owner}/{repo.name}"
    if repo.family == "github":
        url = f"{base}/blob/{pin}/{quoted_path}"
    elif repo.family == "gitlab":
        url = f"{base}/-/blob/{pin}/{quoted_path}"
    else:
        url = f"{base}/src/commit/{pin}/{quoted_path}"
    if start is not None:
        if repo.family == "gitlab":
            url += f"#L{start}"
            if end is not None and end != start:
                url += f"-{end}"
        else:
            url += f"#L{start}"
            if end is not None and end != start:
                url += f"-L{end}"
    return url


def _source_ref_markdown(profile: dict, value) -> str:
    """Render source_ref values as pinned links when their forge is known.

    A profile can declare two repositories: the libretro port in ``source`` and
    the original emulator in ``upstream``. Which of the two carries a given
    path cannot be decided without reading their trees, and this generator runs
    offline. Rather than guess, an unattributable path is rendered as plain
    code: a citation with no link still names the file and the lines, while a
    link to the wrong repository is a false citation.
    """
    rendered_groups: list[str] = []
    path_re = re.compile(r"^[A-Za-z0-9_.@/+~-]+$")
    for label, refs in source_ref_values(value):
        candidates = _forge_sources(profile, label)
        rendered: list[str] = []
        for part in split_source_ref(refs):
            display = part.path
            if part.start is not None:
                display += f":{part.start}"
                if part.end is not None and part.end != part.start:
                    display += f"-{part.end}"

            selected: tuple[upstream.Repo, str] | None = None
            real_path = part.path
            if path_re.fullmatch(part.path) and candidates:
                for repo, pin in candidates:
                    prefix = f"{repo.name}/"
                    if part.path.startswith(prefix):
                        selected = (repo, pin)
                        real_path = part.path[len(prefix):]
                        break
                if selected is None and len(candidates) == 1:
                    selected = candidates[0]

            if selected is None:
                rendered.append(f"`{display}`")
            else:
                repo, pin = selected
                url = _source_permalink(
                    repo, pin, real_path, part.start, part.end
                )
                rendered.append(f"[`{display}`]({url})")

        text = ", ".join(rendered) if rendered else f"`{refs}`"
        if label:
            text = f"**{label}:** {text}"
        rendered_groups.append(text)
    return "; ".join(rendered_groups)


def _admonition_body(text: str) -> str:
    """Indent prose without turning source tokens such as ``#if`` into H1s."""
    escaped = re.sub(r"(?m)^(\s*)#", r"\1\\#", text)
    return escaped.replace("\n", "\n    ")


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


def _icon_name(manufacturer: str, console_name: str) -> str:
    return f"{manufacturer} - {console_name}".replace("/", " ")


def _icon_url(icon_name: str) -> str:
    return f"{SYSTEM_ICON_BASE}/{urllib.parse.quote(icon_name)}.png"


def prime_system_icons(names: set[str]) -> None:
    """Record which system icons upstream actually serves.

    Results persist in ``.cache`` so later runs skip the network. Names that
    cannot be checked stay unavailable: the site never links an image it has
    not seen answer.
    """
    cached: dict[str, bool] = {}
    if ICON_CACHE_PATH.exists():
        try:
            with open(ICON_CACHE_PATH) as f:
                cached = json.load(f)
        except (json.JSONDecodeError, OSError):
            cached = {}

    unknown = sorted(n for n in names if n not in cached)
    if unknown:
        def check(name: str) -> tuple[str, bool | None]:
            """True when served, False when upstream says it is gone.

            None on a transient failure, so a flaky run never records an
            icon as absent for every later build.
            """
            req = urllib.request.Request(_icon_url(name), method="HEAD")
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return name, resp.status == 200
            except urllib.error.HTTPError as exc:
                return name, False if exc.code == 404 else None
            except (urllib.error.URLError, OSError):
                return name, None

        print(f"Checking {len(unknown)} system icons...")
        with ThreadPoolExecutor(max_workers=8) as pool:
            for name, ok in pool.map(check, unknown):
                if ok is not None:
                    cached[name] = ok
        ICON_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ICON_CACHE_PATH, "w") as f:
            json.dump(cached, f, indent=2, sort_keys=True)

    _icon_available.update(cached)
    missing = sum(1 for n in names if not cached.get(n))
    if missing:
        print(f"  {missing} systems have no upstream icon")


def system_icon_markdown(manufacturer: str, console_name: str) -> str:
    """Icon image for a system heading, empty when upstream serves none."""
    name = _icon_name(manufacturer, console_name)
    if not _icon_available.get(name):
        return ""
    return f"![{console_name}]({_icon_url(name)}){{ width=24 }} "

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


# Home page


def generate_home(
    db: dict, coverages: dict, profiles: dict, registry: dict | None = None
) -> str:
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    ts = _timestamp()

    unique = unique_emulator_profiles(profiles)
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
        "BIOS and firmware metadata checked the way each platform checks it, "
        "cross-referenced against revision-pinned emulator source code.",
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
        composition_sentence(db),
        "",
    ]

    # Platforms FIRST (main action)
    lines.extend(
        [
            "## Platforms",
            "",
            "| Icon | Platform | Files | Checked by | Download |",
            "|---|----------|-------|-----------|----------|",
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

    lines.extend(
        [
            "",
            "Checked by is the test each platform runs on its own, replicated "
            "from its source code. RetroArch only looks for the filename; "
            "Batocera compares MD5 checksums, the fingerprint of a file's "
            "contents. "
            "[How each mode works](wiki/verification-modes.md).",
        ]
    )

    catalog_matched = sum(
        1 for f in db.get("files", {}).values() if f.get("provenance")
    )
    if catalog_matched:
        lines.extend(
            [
                "",
                f"**{catalog_matched:,}** files are byte-identical to a dump "
                "catalogued by No-Intro, Redump, or TOSEC, and say so on their "
                "system page. [What that means](provenance.md).",
            ]
        )

    # Quick start (collapsible -- secondary info)
    lines.extend(
        [
            "",
            '??? info "Where to extract"',
            "",
            "    | Platform | Extract to |",
            "    |----------|-----------|",
            "    | RetroArch | `system/` |",
            "    | Batocera | `/userdata/bios/` |",
            "    | BizHawk | `Firmware/` |",
            "    | EmuDeck | `~/Emulation/bios/` |",
            "    | Lakka | `/storage/system/` |",
            "    | MiSTer FPGA | `/media/fat/games/` |",
            "    | ROCKNIX | `/storage/roms/bios/` |",
            "    | Recalbox | `/recalbox/share/bios/` |",
            "    | RetroBat | `bios/` |",
            "    | RetroDECK | `~/retrodeck/` |",
            "    | RetroPie | `~/RetroPie/BIOS/` |",
            "    | RomM | `bios/{platform_slug}/` |",
            "",
            "    The RetroDECK pack already carries its own `bios/` folder, so it "
            "extracts one level above it. Every other pack extracts straight into "
            "the BIOS folder. [Full instructions per setup](which-pack.md).",
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
            "    Platform lists are checked against emulator source code, file "
            "by file where a profile exists ([how far that reaches](gaps.md)). "
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
            "[Dump provenance](provenance.md){ .md-button } "
            "[Data & API](data.md){ .md-button } "
            "[Contributing](contributing.md){ .md-button .md-button--primary }",
            "",
            f'<div class="rb-timestamp">Generated on {ts}.</div>',
        ]
    )

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
        "catalog_matched": sum(
            1 for f in db.get("files", {}).values() if f.get("provenance")
        ),
        "source": REPO_URL,
        "downloads": RELEASE_URL,
    }


def composition_sentence(db: dict) -> str:
    comp = compute_composition(db)
    return (
        f"Of these files, {comp['systems']['files']:,} are console and "
        f"computer system files, {comp['arcade']['files']:,} arcade ROM sets "
        f"(`Arcade/`), and {comp['game_data']['files']:,} game and engine "
        "data (the `RPG Maker/` and `ScummVM/` trees)."
    )


def generate_stats(stats: dict) -> str:
    return json.dumps(stats, indent=2) + "\n"


def _json_text(value) -> str:
    """Stable scalar representation for CSV and SQLite exports."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, bool)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


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


def _platform_export_rows(coverages: dict) -> tuple[list[dict], list[dict]]:
    """Normalized platform summaries and one row per declared file."""
    items: list[dict] = []
    file_rows: list[dict] = []
    for key, coverage in sorted(coverages.items()):
        config = coverage["config"]
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
            "contract": config,
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
                    "variant_group": _json_text(entry.get("variant_group")),
                    "size": entry.get("size"),
                    "sha1": _json_text(entry.get("sha1")),
                    "sha256": _json_text(entry.get("sha256")),
                    "md5": _json_text(entry.get("md5")),
                    "crc32": _json_text(entry.get("crc32")),
                })
    return items, file_rows


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
    twice and drift; both read this one report.
    """
    from common import expand_platform_declared_names
    from cross_reference import cross_reference as run_cross_reference

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

    unique_profiles = {
        k: v
        for k, v in profiles.items()
        if v.get("type") not in ("alias", "test")
    }
    return run_cross_reference(
        unique_profiles, declared, db,
        data_names=data_names, all_declared=all_declared,
    )


def _gap_export_rows(coverages: dict, gap_report: dict | None = None) -> list[dict]:
    """Every gap the site reports, both layers, in one table.

    ``platform`` rows are anomalies against a platform's own BIOS list.
    ``emulator`` rows are files a profiled core loads that no platform
    declares, which is the larger number the gap analysis page leads with.
    A `layer` column keeps the two apart instead of publishing only one.
    """
    rows: list[dict] = []
    for key, coverage in sorted(coverages.items()):
        for detail in coverage.get("details", []):
            if detail.get("status") == "ok" and not detail.get("discrepancy"):
                continue
            rows.append({
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
            })
    for emu_key, data in sorted((gap_report or {}).items()):
        systems = ";".join(str(s) for s in data.get("systems", []) or [])
        for gap in data.get("gap_details", []) or []:
            rows.append({
                "layer": "emulator",
                "platform_id": "",
                "platform": "",
                "emulator": data.get("emulator", emu_key),
                "system": systems,
                "name": gap.get("name", ""),
                "status": gap.get("source", ""),
                "required": bool(gap.get("required", False)),
                "in_repo": bool(gap.get("in_repo", False)),
                "reason": gap.get("note", ""),
                "discrepancy": "",
            })
        for entry in data.get("unsourceable", []) or []:
            rows.append({
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
            })
    return rows


def _cross_reference_export_rows(coverages: dict, profiles: dict) -> list[dict]:
    from common import resolve_platform_cores

    unique = {
        key: value
        for key, value in profiles.items()
        if value.get("type") not in ("alias", "test")
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
                region TEXT, variant_group TEXT, size INTEGER,
                sha1 TEXT, sha256 TEXT, md5 TEXT, crc32 TEXT
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
                in_repo TEXT, reason TEXT, discrepancy TEXT
            );
            CREATE INDEX files_name_idx ON files(name);
            CREATE INDEX files_md5_idx ON files(md5);
            CREATE INDEX files_sha256_idx ON files(sha256);
            CREATE INDEX platform_files_name_idx ON platform_files(name);
            CREATE INDEX emulator_files_name_idx ON emulator_files(name);
            CREATE INDEX gaps_status_idx ON gaps(layer, status);
        """)
        metadata = {
            "schema_version": "1",
            "generated_at": str(db.get("generated_at") or _timestamp()),
            "source": REPO_URL,
            "scope": "metadata only; no BIOS or firmware payload bytes",
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
            ":variant_group, :size, :sha1, :sha256, :md5, :crc32)",
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
            "INSERT INTO gaps VALUES "
            "(:layer, :platform_id, :platform, :emulator, :system, :name, "
            ":status, :required, :in_repo, :reason, :discrepancy)",
            gap_rows,
        )
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()
    os.replace(temp_path, destination)


def generate_data_exports(
    docs: Path,
    db: dict,
    coverages: dict,
    profiles: dict,
    stats: dict,
    gap_report: dict | None = None,
) -> list[dict]:
    """Create versioned static API, CSV and SQLite metadata snapshots."""
    api = docs / "api" / "v1"
    downloads = docs / "downloads"
    schemas_dest = api / "schemas"
    for directory in (api, downloads, schemas_dest):
        directory.mkdir(parents=True, exist_ok=True)

    generated_at = str(db.get("generated_at") or _timestamp())
    platform_items, platform_files = _platform_export_rows(coverages)
    emulator_items = _emulator_export_items(profiles)
    gap_rows = _gap_export_rows(coverages, gap_report)
    cross_rows = _cross_reference_export_rows(coverages, profiles)

    envelopes = {
        "platforms.json": ("platforms", platform_items),
        "emulators.json": ("emulators", emulator_items),
        "gaps.json": ("verification-and-coverage-gaps", gap_rows),
    }
    for filename, (kind, items) in envelopes.items():
        document = {
            "schema_version": 1,
            "generated_at": generated_at,
            "kind": kind,
            "count": len(items),
            "items": items,
        }
        write_if_changed(
            str(api / filename),
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
    write_if_changed(str(api / "stats.json"), generate_stats(stats))
    write_if_changed(
        str(api / "database.json"),
        json.dumps(db, ensure_ascii=False, indent=2) + "\n",
    )

    schema_names = (
        "database.schema.json", "emulator.schema.json", "platform.schema.json",
        "site-api-envelope.schema.json", "stats.schema.json",
    )
    for schema_name in schema_names:
        shutil.copy2(Path("schemas") / schema_name, schemas_dest / schema_name)

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
                "required", "region", "variant_group", "size", "sha1",
                "sha256", "md5", "crc32",
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
                "discrepancy",
            ],
            gap_rows,
        ),
    )
    _write_sqlite_export(
        downloads / "retrobios.sqlite", db, platform_items, platform_files,
        emulator_items, gap_rows,
    )

    assets = [
        (api / "database.json", "Content database", "application/json", "schemas/database.schema.json"),
        (api / "platforms.json", "Platform contracts", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "emulators.json", "Emulator profiles", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "gaps.json", "Verification and coverage gaps", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "stats.json", "Project statistics", "application/json", "schemas/stats.schema.json"),
        (downloads / "files.csv", "File hashes CSV", "text/csv", None),
        (downloads / "platform-files.csv", "Platform declarations CSV", "text/csv", None),
        (downloads / "cross-reference.csv", "Cross-reference CSV", "text/csv", None),
        (downloads / "gaps.csv", "Verification and coverage gaps CSV", "text/csv", None),
        (downloads / "retrobios.sqlite", "SQLite snapshot", "application/vnd.sqlite3", None),
    ]
    catalog_items: list[dict] = []
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
    catalog = {
        "schema_version": 1,
        "generated_at": generated_at,
        "kind": "catalog",
        "count": len(catalog_items),
        "items": catalog_items,
    }
    write_if_changed(
        str(api / "catalog.json"),
        json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return catalog_items


def generate_data_page(exports: list[dict]) -> str:
    lines = [
        f"# Data & API - {SITE_NAME}",
        "",
        "RetroBIOS publishes the same metadata used by its verifier, pack builder "
        "and website as versioned static files. No account or API key is required.",
        "",
        "[API catalog](api/v1/catalog.json){ .md-button .md-button--primary } "
        "[SQLite snapshot](downloads/retrobios.sqlite){ .md-button }",
        "",
        "## Stable JSON endpoints",
        "",
        "| Dataset | Endpoint | Schema | Size |",
        "|---------|----------|--------|-----:|",
    ]
    for item in exports:
        if item["media_type"] != "application/json":
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
        "Every JSON document carries `schema_version`. Breaking changes use a new "
        "URL prefix (`/api/v2/`); fields may only be added compatibly within v1.",
        "",
        "## Bulk downloads",
        "",
        "| Export | Format | Size | SHA256 |",
        "|--------|--------|-----:|--------|",
    ])
    for item in exports:
        if item["media_type"] == "application/json":
            continue
        lines.append(
            f"| [{item['title']}]({item['url']}) | `{item['media_type']}` | "
            f"{_fmt_size(item['bytes'])} | `{item['sha256']}` |"
        )
    lines.extend([
        "",
        "The SQLite file contains indexed tables for content hashes, provenance "
        "catalog matches, platform declarations, emulator profiles and current "
        "gaps. It contains metadata only, never BIOS or firmware bytes.",
        "",
        "The gaps dataset carries both layers behind one `layer` column: "
        "`platform` rows are anomalies against a platform's own BIOS list, "
        "`emulator` rows are files a profiled core loads that no platform "
        "declares. The two answer different questions and are not comparable "
        "totals.",
        "",
        "## Semantics and limits",
        "",
        "Treat four questions separately: content identity (hashes), presence in "
        "the collection, acceptance by a specific emulator, and catalog provenance. "
        "One does not imply the others. In particular, presence, a matching dump "
        "catalog, or emulator compatibility is not a statement about copyright, "
        "ownership, or redistribution rights.",
        "",
        f"The data can be newer than the [latest published pack]({RELEASE_URL}); "
        "pack publication is manual and only occurs after all release gates pass.",
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
        "index.md": SITE_NAME,
        "platforms/index.md": "Platforms",
        "systems/index.md": "Systems",
        "emulators/index.md": "Emulators",
        "wiki/index.md": "Guide and methodology",
    }
    if key in index_titles:
        return index_titles[key]
    if key.startswith("emulators/"):
        return f"{title} emulator firmware"
    if key.startswith("systems/"):
        return f"{title} systems"
    return title


def _plain_markdown(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"!\[([^]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[`*_~]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _page_description(markdown: str, relative: Path, title: str) -> str:
    key = relative.as_posix()
    specific = {
        "index.md": "Source-traced BIOS and firmware metadata, platform verification, emulator profiles, gaps and reproducible retrogaming data exports.",
        "data.md": "Versioned RetroBIOS JSON API, CSV exports, SQLite snapshot, schemas, checksums and data interpretation guidance.",
        "cross-reference.md": "Cross-reference from retrogaming platforms to emulator cores, systems, upstream projects and profiled firmware files.",
        "gaps.md": "Current RetroBIOS verification gaps, platform-to-emulator divergences, missing files and documented source limitations.",
        "provenance.md": "Hash-based comparison of RetroBIOS metadata with No-Intro, Redump and TOSEC catalog snapshots.",
        "which-pack.md": "One-line automatic RetroBIOS installation and platform-specific pack destinations, with verification and release caveats.",
    }
    if key in specific:
        return specific[key]
    if key.startswith("platforms/") and relative.stem != "index":
        return f"{title}: declared BIOS contract, verification mode, coverage, destinations and emulator complement."
    if key.startswith("emulators/") and relative.stem != "index":
        return f"{title}: source-pinned emulator firmware profile with paths, hashes, requirements and validation behavior."
    if key.startswith("systems/") and relative.stem != "index":
        return f"{title}: indexed firmware files, hashes, variants, provenance and platform or emulator usage."

    paragraphs = re.split(r"\n\s*\n", markdown)
    for paragraph in paragraphs:
        stripped = paragraph.strip()
        if (
            not stripped
            or stripped.startswith(("#", "|", "```", "???", "<", "- ", "* "))
        ):
            continue
        plain = _plain_markdown(stripped)
        if len(plain) >= 35:
            return plain[:157].rstrip(" ,;:-") + ("..." if len(plain) > 157 else "")
    return f"{title}: RetroBIOS source-traced retrogaming firmware reference."


def decorate_markdown_pages(docs: Path) -> None:
    """Add per-page descriptions and machine-readable structured data."""
    for path in sorted(docs.rglob("*.md")):
        relative = path.relative_to(docs)
        if relative.parts and relative.parts[0] == "superpowers":
            continue
        markdown = path.read_text(encoding="utf-8")
        if markdown.startswith("---\n") and "generated_by: retrobios-site" in markdown[:300]:
            end = markdown.find("\n---\n", 4)
            if end != -1:
                markdown = markdown[end + 5:].lstrip("\n")
                script_end = markdown.find("</script>\n\n")
                if markdown.startswith('<script type="application/ld+json">') and script_end != -1:
                    markdown = markdown[script_end + len("</script>\n\n"):]
        elif markdown.startswith("---\n"):
            continue

        title = _page_title(markdown, relative)
        browser_title = _browser_title(relative, title)
        description = _page_description(markdown, relative, title)
        if relative.name == "index.md":
            page_path = "" if len(relative.parts) == 1 else "/".join(relative.parts[:-1]) + "/"
        else:
            page_path = relative.with_suffix("").as_posix() + "/"
        canonical = urllib.parse.urljoin(SITE_URL, page_path)
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
        }
        structured_json = json.dumps(
            structured, ensure_ascii=False, separators=(",", ":")
        ).replace("</", "<\\/")
        front_matter = (
            "---\n"
            "generated_by: retrobios-site\n"
            f"title: {json.dumps(browser_title, ensure_ascii=False)}\n"
            f"description: {json.dumps(description, ensure_ascii=False)}\n"
            "---\n\n"
            '<script type="application/ld+json">\n'
            f"{structured_json}\n"
            "</script>\n\n"
        )
        write_if_changed(str(path), front_matter + markdown)


# Platform pages


def generate_platform_index(coverages: dict, registry: dict | None = None) -> str:
    total_present = sum(c["present"] for c in coverages.values())

    lines = [
        f"# Platforms - {SITE_NAME}",
        "",
        f"{len(coverages)} supported platforms with "
        f"{total_present:,} verified files.",
        "",
        "| Platform | Files | Checked by | Status | Download |",
        "|----------|-------|-----------|--------|----------|",
    ]

    mode_labels = {
        "md5": '<span class="rb-badge rb-badge-success">MD5</span>',
        "sha1": '<span class="rb-badge rb-badge-success">SHA1</span>',
        "existence": '<span class="rb-badge rb-badge-info">existence</span>',
    }

    archived_any = False
    for name, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]

        mode_html = mode_labels.get(
            cov["mode"],
            f'<span class="rb-badge rb-badge-muted">{cov["mode"]}</span>',
        )
        status = (registry or {}).get(name, {}).get("status", "active")
        if status == "archived":
            archived_any = True
            status_html = '<span class="rb-badge rb-badge-muted">archived</span>'
        else:
            status_html = '<span class="rb-badge rb-badge-success">active</span>'

        lines.append(
            f"| [{display}]({name}.md) | "
            f"{cov['present']:,} | {mode_html} | {status_html} | "
            f"[Pack]({RELEASE_URL}){{ .md-button .md-button--primary }} |"
        )

    lines.extend(
        [
            "",
            "Checked by is the test each platform runs on its own, replicated "
            "from its source code. "
            "[How each mode works](../wiki/verification-modes.md).",
        ]
    )

    if archived_any:
        lines.extend(
            [
                "",
                "An archived platform keeps its configuration and still gets a "
                "pack, but upstream is no longer scraped on a schedule.",
            ]
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
    mode_badge = (
        "rb-badge-success" if mode in ("md5", "sha1") else "rb-badge-info"
    )

    lines = [
        f"# {display} - {SITE_NAME}",
        "",
        logo_md,
    ]

    if (registry or {}).get(name, {}).get("status") == "archived":
        lines.extend(
            [
                '!!! warning "Archived platform"',
                "",
                "    The configuration is kept and packs are still built, but "
                "upstream is no longer scraped on a schedule, so the file list "
                "reflects the last sync rather than today's upstream.",
                "",
            ]
        )

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
            '<span class="rb-stat-label">Checked by</span>',
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


def generate_provenance_page(db: dict, report: dict) -> str:
    """Page explaining the verified dump badges and listing catalog gaps."""
    # Scoped to system files: these catalogs index console and computer dumps,
    # so arcade ROM sets and engine data can never match and would only make
    # the ratio look worse than the work behind it.
    matched_files = 0
    for entry in db.get("files", {}).values():
        if not entry.get("provenance"):
            continue
        parts = entry.get("path", "").split("/")
        top = parts[1] if len(parts) > 1 else ""
        if top != "Arcade" and top not in GAME_DATA_TOPS:
            matched_files += 1
    total_files = compute_composition(db)["systems"]["files"]

    lines = [
        f"# Dump provenance - {SITE_NAME}",
        "",
        f"**{matched_files:,}** of {total_files:,} system files match an entry "
        "in a dump-preservation catalog. Those files carry a "
        '<span class="rb-badge rb-badge-success">Verified dump</span> badge on '
        "the [system pages](systems/index.md). Arcade ROM sets and engine data "
        "sit outside what those catalogs index, so they are left out of the "
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
        "modern console firmware updates, game data such as `prboom.wad`, and "
        "arcade sets tracked by MAME driver source instead.",
        "",
        "When the two views disagree, this project follows the code, because "
        "that is what decides whether your emulator boots. The reasoning is in "
        "the [FAQ](wiki/faq.md#are-these-files-verified-against-original-"
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
            f"{len(data['covered_dats'])} | {data['imported_at']} |"
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

    total_missing = sum(len(d["missing"]) for d in report.values())
    lines.extend(
        [
            "## Wanted: catalogued dumps this project does not have",
            "",
            f"The tables below list **{total_missing:,}** dumps a catalog "
            "describes and the collection lacks. Nothing here ships in any "
            "pack: it is an acquisition list, published with hashes so anyone "
            "can check a personal collection against it. A contribution "
            "matching one of these hashes is welcome: see "
            "[Contributing](contributing.md).",
            "",
        ]
    )

    for source, data in report.items():
        if not data["missing"]:
            continue
        label = _PROVENANCE_LABELS.get(source, source)
        by_dat: dict[str, list] = {}
        for entry in data["missing"]:
            by_dat.setdefault(entry.get("dat", ""), []).append(entry)
        lines.extend([f"### {label}", ""])
        for dat in sorted(by_dat):
            entries = by_dat[dat]
            lines.extend([f'??? note "{dat} ({len(entries)})"', ""])
            lines.append("    | Name | Description | SHA1 |")
            lines.append("    |------|-------------|------|")
            for entry in sorted(entries, key=lambda e: e["name"]):
                sha1 = entry.get("sha1") or "-"
                # A pipe in catalog text would split the markdown table row
                name = entry["name"].replace("|", "-")
                desc = (entry.get("description") or "").replace("|", "-")
                lines.append(f"    | `{name}` | {desc} | `{sha1}` |")
            lines.append("")

    lines.append(f'<div class="rb-timestamp">Generated on {_timestamp()}.</div>')
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
        icon_md = system_icon_markdown(manufacturer, console_name)
        lines.append(f"## {icon_md}{console_name}")
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
            provenance = f.get("provenance", {})
            if provenance:
                prov_badges = " ".join(
                    f'<span class="rb-badge rb-badge-success" '
                    f'title="{_prov_title(data)}">'
                    f"[{_PROVENANCE_LABELS.get(s, s)}](../provenance.md#{s})</span>"
                    for s, data in sorted(provenance.items())
                )
                lines.append(f"- Verified dump: {prov_badges}")
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


def _file_badges(f: dict, in_repo: bool) -> list[str]:
    """The status chips shown beside a file name.

    Fourteen independent optional fields, each contributing at most one
    chip. Kept apart from the rest of the row so the field-by-field
    rendering stays readable.
    """
    required = f.get("required", False)
    hle = f.get("hle_fallback", False)
    mode = f.get("mode", "")
    category = f.get("category", "")
    region = f.get("region", "")
    storage = f.get("storage", "")
    bundled = f.get("bundled", False)
    embedded = f.get("embedded", False)
    has_builtin = f.get("has_builtin", False)
    archive = f.get("archive", "")
    ftype = f.get("type", "")
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

    return badges


def _render_emulator_file(
    f: dict,
    profile: dict,
    platform_files: dict | None,
    files: list,
    _file_available,
) -> list[str]:
    """Render one row of an emulator profile's file table.

    Split out of generate_emulator_page, where it was a 228-line loop body
    carrying most of that function's branching: thirty-odd optional fields,
    each with its own badge, hash line or note.
    """
    lines: list[str] = []
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

    badges = _file_badges(f, in_repo)
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
        details.append(
            f"Source: {_source_ref_markdown(profile, source_ref)}"
        )
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
    return lines


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
        ("verification", "Checked by"),
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
    if profile.get("source_ref"):
        lines.append(
            f"| Source ref | {_source_ref_markdown(profile, profile['source_ref'])} |"
        )
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
        indented = _admonition_body(notes)
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
                f, db_files,
            )
            if src is not None:
                return True
            path_field = f.get("path", "")
            if path_field and path_field != fname:
                src = _resolve_source(
                    path_field, by_name, by_name_lower, data_names,
                    by_path_suffix, f, db_files,
                )
                if src is not None:
                    return True
            md5_raw = f.get("md5", "")
            if md5_raw:
                for md5_val in parse_md5_list(md5_raw):
                    if by_md5.get(md5_val):
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
            lines.extend(
                _render_emulator_file(
                    f, profile, platform_files, files, _file_available
                )
            )

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
    registry: dict | None = None,
    gap_report: dict | None = None,
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
        "[Download gaps CSV](downloads/gaps.csv){ .md-button } "
        "[Open gaps API](api/v1/gaps.json){ .md-button } "
        "[All data exports](data.md){ .md-button }",
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
        "## What Each Pack Contains",
        "",
        "| Platform | On its BIOS list | Files its emulators load | Checked by |",
        "|----------|-----------------:|-------------------------:|------------|",
    ])

    mode_labels = {
        "md5": "MD5 hash",
        "sha1": "SHA1 hash",
        "existence": "file presence",
    }

    def _ratio(done: int, total: int) -> str:
        """A collected-over-needed cell, flagged when short."""
        if not total:
            return "-"
        cell = f"{done:,}/{total:,}"
        if done < total:
            return f'<span class="rb-badge rb-badge-danger">{cell}</span>'
        return cell

    for pname, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        core_total = (
            cov["core_present"] + cov["core_missing"] + cov["core_unsourceable"]
        )
        lines.append(
            f"| [{display}](platforms/{pname}.md) "
            f"| {_ratio(cov['present'], cov['total'])} "
            f"| {_ratio(cov['core_present'], core_total)} "
            f"| {mode_labels.get(cov['mode'], cov['mode'])} |"
        )
    lines.extend([
        "",
        "Each fraction is what the pack has over what is needed, counting "
        "required and optional files alike since both ship. The first column "
        "is the BIOS list the platform publishes. The second counts files its "
        "emulators load that this list never mentions, found by reading their "
        "source code, and it is routinely several times larger; a short "
        "fraction is flagged and named in the sections below. That second "
        "number is a floor, not a ceiling: an emulator that accepts any file "
        "handed to it names none in its code, so nothing there can be counted. "
        "Checked by is the test the platform runs on its own, replicated here "
        "from its source code "
        "([how each one works](wiki/verification-modes.md)).",
        "",
        "## Corroboration Against Emulator Source",
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
            prof_cell = f"{gt.get('with_profile', 0)} ({prof_pct})"
            gt_pct = f"{gt['with_validation'] / gt['total'] * 100:.0f}%"
            gt_cell = f"{gt['with_validation']} ({gt_pct})"
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
        s = diff_platform_truth(truth_data, cov["config"])["summary"]
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
        "## Platform Lists vs Emulator Source",
        "",
        "Platform file lists are scraped as-is from each upstream project. "
        "Emulator profiles are read from source code. The two do not always "
        "agree, and this table counts the differences. Packs follow the "
        "platform contract; these numbers show where that contract diverges "
        "from what the code loads.",
        "",
        "| Platform | Missing from list | Phantom | Hash conflict | Required status |",
        "|----------|------------------:|--------:|--------------:|----------------:|",
        *div_rows,
        "",
        "- **Missing from list**: a profiled emulator loads the file, the platform list does not mention it",
        "- **Phantom**: on the platform list, loaded by no profiled emulator",
        "- **Hash conflict**: the platform list and the emulator source expect different hashes",
        "- **Required status**: required/optional differs between list and code",
        "",
        "A dash means no profiled emulator overlaps the platform's systems, "
        "so there is nothing to compare: the platform's own source is the "
        "only authority for its files.",
        "",
        "The same comparison drives `scripts/exporter/`: each platform's "
        "corrected list can be regenerated in its native format "
        "(System.dat, es_bios.xml, batocera-systems.json, ...).",
        "",
    ])

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

    unique_profiles = {
        k: v
        for k, v in profiles.items()
        if v.get("type") not in ("alias", "test")
    }
    relevant_set: set[str] = set()
    for _name, cov in coverages.items():
        matched = resolve_platform_cores(cov["config"], unique_profiles)
        relevant_set.update(matched)
    if gap_report is None:
        gap_report = build_emulator_gap_report(profiles, coverages, db, data_names)
    report_all = gap_report

    src_totals: dict[str, int] = {"bios": 0, "data": 0, "large_file": 0, "missing": 0}
    total_undeclared = 0
    emulator_gaps = []

    for emu_name, data in sorted(report_all.items()):
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
            "This counts every profiled emulator, including those no platform "
            "ships yet, so it reaches past what the pack tables above measure: "
            "those cover only the emulators each platform actually ships. "
            "Whatever is not in the collection is an acquisition target, named "
            "per emulator below.",
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
                    f"{plat_badges} | "
                    f"{_source_ref_markdown(profiles[m['emu_key']], m['source_ref'])} |"
                )
            lines.append("")

    # ---- Section 4: Acknowledged gaps (unsourceable files) ----

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
                f"| {_source_ref_markdown(profiles[u['emu_key']], u['source_ref'])} |"
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
        "[Download cross-reference CSV](downloads/cross-reference.csv){ .md-button } "
        "[Open emulator API](api/v1/emulators.json){ .md-button } "
        "[All data exports](data.md){ .md-button }",
        "",
    ]

    # Per platform
    for pname in sorted(coverages.keys(), key=lambda x: coverages[x]["platform"]):
        cov = coverages[pname]
        display = cov["platform"]
        config = cov["config"]
        platform_cores = config.get("cores", [])

        lines.append(f'??? abstract "{display}"')
        lines.append("")
        lines.append(
            f"    [Open {display} platform profile](platforms/{pname}.md)"
            "{ .md-button }"
        )
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
4. Open a Pull Request - hashes are verified automatically and reported as a comment

The [dump provenance](provenance.md) page lists catalogued dumps still missing
from the collection, with their hashes. A file matching one of those is the
most useful contribution.

## Add a platform

1. Create a scraper in `scripts/scraper/` (inherit `BaseScraper`)
2. Read the platform's upstream source to determine how it checks BIOS files
3. Add an entry to `platforms/_registry.yml`
4. Generate the platform YAML config
5. Test: `python scripts/verify.py --platform <name>`

Full walkthrough: [adding a platform](wiki/adding-a-platform.md).

## Add an emulator profile

1. Clone the emulator's source code, upstream and libretro port
2. Trace the file loading from the entry point, not from a keyword grep
3. Document every file the code loads, with a `source_ref` line reference
4. Write the YAML to `emulators/<name>.yml`
5. Test: `python scripts/cross_reference.py --emulator <name>`

Full walkthrough: [profiling guide](wiki/profiling.md).

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

Contributors who add platform support are credited in the README, on this site,
and in the BIOS packs.
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
        '  "adler32": "...",',
        '  "provenance": {',
        '    "redump": {"dat": "...", "name": "...", "description": "..."}',
        "  }",
        "}",
        "```",
        "",
        "`provenance` maps each catalog that lists the file to the DAT and entry "
        "it was matched against. It is present only when the file matches a "
        "snapshot under `provenance/`; the join runs by SHA1 first, then by "
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
        "`resolve_local_file` tries these steps in order:",
        "",
        "1. SHA1 exact match; every other declared hash must agree with the record",
        "2. SHA256 exact match, with the same all-declarations-must-agree rule",
        "3. CRC32 plus declared size, only when no stronger hash is present",
        "4. MD5 direct lookup (including explicitly supported truncated MD5 values)",
        "5. Path suffix lookup for regional variants; with hashes it is accepted only if those hashes match",
        "6. Name and alias lookup only when no content hash was declared",
        "7. Candidate inspection for composite ZIP MD5 or direct MD5; a named candidate with the wrong content returns `hash_mismatch`",
        "8. `zipped_file` content match via the inner-ROM MD5 index",
        "9. MAME clone fallback, only for declarations without a content hash",
        "10. Data-directory scan; declared hashes are computed over the candidate before it is accepted",
        "11. Agnostic size/path fallback, only for declarations without a content hash",
        "",
        "A filename or destination can never override a declared hash. The first "
        "evidence-compatible match wins; otherwise the resolver reports a mismatch "
        "or absence. Steps and their return codes are described in "
        "[verification modes](verification-modes.md#file-resolution-chain).",
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
        "from these same structures. Start with the [Data & API](../data.md) "
        "catalog; each downloadable artifact carries a SHA256 in "
        "`api/v1/catalog.json`.",
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
    rel = RELEASE_URL
    return f"""\
# Download

Some retro consoles need firmware files (commonly called BIOS) to run games.
Without them, the emulator either refuses to start the game or runs it with
reduced accuracy. RetroBIOS maps those requirements to source-traced emulator
profiles and verifies local content against the evidence each platform exposes.

This page picks the right pack for a setup. For BIOS directory paths per
platform, verification, and the CLI, see
[Getting started](wiki/getting-started.md).

## Quick install

One line detects the platform and BIOS directory, downloads only missing or
incorrect files, verifies their hashes, and installs them atomically. The small
bootstrap checks the Python installer against an embedded SHA-256 before running
it, and the installer reads its file list from that same revision.

**Linux / Mac / Steam Deck:**

```sh
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh
```

**Windows (PowerShell):**

```powershell
iwr -useb https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1 | iex
```

That is the complete default flow. Extra copies into detected standalone
emulator directories are deliberately opt-in with `--standalone-copies`, so
automatic setup never writes outside the selected platform tree unexpectedly.
Use `python install.py --check` from a checkout for a read-only verification.

---

## Manual download

Pick the pack that matches the setup from the [latest release]({rel}),
download it, and extract the files into the BIOS folder listed below.
The metadata and website can be newer than that release: pack publication is
manual and only happens after the release gates pass.

Packs over 2 GB are split into numbered volumes (`.zip.001`, `.zip.002`).
Download every part, then open the `.001` file with 7-Zip or PeaZip, which
extract the whole archive directly. To join the parts manually instead:

- Linux/macOS: `cat PackName.zip.0* > PackName.zip`
- Windows (cmd): `copy /b PackName.zip.001+PackName.zip.002 PackName.zip`

### Steam Deck

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| [EmuDeck](https://www.emudeck.com/) | Installs and configures multiple emulators, adds each game to the Steam library | [EmuDeck]({rel}) | `~/Emulation/bios/` |
| [RetroDECK](https://retrodeck.net/) | Single Flatpak app, all emulators bundled, one-click install from Discover | [RetroDECK]({rel}) | `~/retrodeck/` (the pack carries its own `bios/`) |
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

### Handhelds

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| Android (Retroid Pocket, Odin, etc.) | Most Android handhelds run RetroArch | [RetroArch]({rel}) | `RetroArch/system/` on internal storage or SD card |
| [ROCKNIX](https://rocknix.org/) | Linux OS for ARM and x86 handhelds (RG35XX, RG552, Deck) | [ROCKNIX]({rel}) | `/storage/roms/bios/`, over SSH or the network share |
| [Batocera](https://batocera.org/) | Also images many handhelds | [Batocera]({rel}) | `/userdata/bios/` |

### FPGA

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| [MiSTer FPGA](https://mister-devel.github.io/MkDocs_MiSTer/) | Hardware-level recreation of consoles on a DE10-Nano board | [MiSTer FPGA]({rel}) | `/media/fat/games/`, one subfolder per core |

### Self-hosted ROM manager

| Setup | What it is | Pack | Extract to |
|-------|-----------|------|-----------|
| [RomM](https://github.com/rommapp/romm) | Web-based ROM manager, plays games in the browser via EmulatorJS | [RomM]({rel}) | The `bios` folder in the RomM library, one subfolder per system |

---

## Full pack or Platform pack?

Each platform has two pack types on the [latest release]({rel}).

**Full pack** (recommended)

Contains the platform's own BIOS list plus all files needed by each
emulator core available on that platform. This covers alternate cores,
optional firmware that improves accuracy, and edge cases. Larger download,
and the best default when storage is not constrained. It is not a guarantee:
source profiles can document missing, user-provided or unsourceable files, all
of which remain visible in the [gap analysis](gaps.md).

**Platform pack**

Contains only the files the platform officially checks for. Much smaller
download. Good for limited storage (SD cards, handhelds) or setups that
only use default cores.

When in doubt, take the full pack and verify it against the platform page.

---

## After extraction

Launch a game and use the emulator's firmware status screen where available.
Most supported frontends find files in the documented directory automatically;
standalone emulators may still need their BIOS path configured.

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
        {"Dump provenance": "provenance.md"},
        {"Data & API": "data.md"},
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
    js_src = Path("docs_assets") / "site.js"
    js_dest = docs / "javascripts" / "site.js"
    if js_src.exists():
        js_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(js_src, js_dest)

    # mkdocs writes sitemap.xml but no robots.txt, so nothing points a crawler
    # at it. Everything published here is meant to be indexed.
    write_if_changed(
        str(docs / "robots.txt"),
        "User-agent: *\nAllow: /\n\nSitemap: https://abdess.github.io/retrobios/sitemap.xml\n",
    )

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
            registry = (yaml_load(f) or {}).get("platforms", {})

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

    stats = compute_stats(db, coverages, profiles)
    stats["composition"] = compute_composition(db)
    write_if_changed(str(docs / "stats.json"), generate_stats(stats))

    # Computed once: the gap analysis page and the published gaps export must
    # report the same files.
    gap_report = build_emulator_gap_report(profiles, coverages, db, suppl_names)

    print("Generating static API and bulk data exports...")
    exports = generate_data_exports(
        docs, db, coverages, profiles, stats, gap_report
    )
    write_if_changed(str(docs / "data.md"), generate_data_page(exports))

    # Build system_id -> manufacturer page map (needed by all generators)
    print("Building system cross-reference map...")
    manufacturers = _group_by_manufacturer(db)
    _build_system_page_map_from_data(manufacturers, coverages, db)
    print(f"  {len(_system_page_map)} system IDs mapped to pages")

    # Generate platform pages
    print("Generating platform pages...")
    write_if_changed(
        str(docs / "platforms" / "index.md"),
        generate_platform_index(coverages, registry),
    )
    for name, cov in coverages.items():
        write_if_changed(
            str(docs / "platforms" / f"{name}.md"),
            generate_platform_page(name, cov, registry, emulator_files),
        )

    # Generate system pages
    print("Generating system pages...")

    prime_system_icons({
        _icon_name(mfr, console)
        for mfr, consoles in manufacturers.items()
        for console in consoles
    })

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
    public_profiles = {
        name: profile
        for name, profile in profiles.items()
        if profile.get("type") not in ("alias", "test")
    }
    for name, profile in public_profiles.items():
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
        generate_gap_analysis(
            profiles, coverages, db, suppl_names, registry, gap_report
        ),
    )

    # Generate dump provenance page
    print("Generating dump provenance page...")
    provenance_report = build_report(db, load_provenance_snapshots())
    write_if_changed(
        str(docs / "provenance.md"), generate_provenance_page(db, provenance_report)
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

    print("Adding page metadata and structured data...")
    decorate_markdown_pages(docs)

    # Update mkdocs.yml nav section only (avoid yaml.dump round-trip mangling quotes)
    print("Updating mkdocs.yml nav...")
    nav = generate_mkdocs_nav(coverages, manufacturers, profiles)
    nav_yaml = yaml.dump(
        {"nav": nav}, default_flow_style=False, sort_keys=False, allow_unicode=True
    )

    # Rewrite mkdocs.yml entirely (static config + generated nav)
    mkdocs_static = """\
site_name: RetroBIOS
site_description: Source-verified BIOS and firmware packs for RetroArch, Batocera,
  Recalbox, Lakka, RetroPie, EmuDeck, RetroBat, RetroDECK, RomM, BizHawk, ROCKNIX
  and MiSTer FPGA.
site_url: https://abdess.github.io/retrobios/
repo_url: https://github.com/Abdess/retrobios
repo_name: Abdess/retrobios
# Almost every page is generated from platforms/, emulators/ and database.json,
# so a per-page edit link would point at a file that does not exist.
edit_uri: ''
# Local implementation plans are preserved in docs/ for development sessions,
# but are not part of the public reference site.
exclude_docs: |
  superpowers/**
copyright: MIT for the tooling. BIOS and firmware files are third-party system
  software, preserved for personal backup, archival and interoperability.
theme:
  name: material
  # Open Graph tags live in overrides/main.html: the social plugin that
  # would otherwise emit them needs Pillow and CairoSVG only to render a
  # preview image the pages do not need.
  custom_dir: docs_assets/overrides
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
  - navigation.instant
  - navigation.instant.prefetch
  - navigation.instant.progress
  - navigation.tabs
  - navigation.tabs.sticky
  - navigation.sections
  - navigation.top
  - navigation.tracking
  - navigation.indexes
  # 400+ pages: pruning keeps the navigation out of every page's HTML.
  - navigation.prune
  - navigation.footer
  - search.suggest
  - search.highlight
  - search.share
  - content.code.copy
  - content.tabs.link
  - toc.follow
extra_css:
- stylesheets/extra.css
extra_javascript:
- javascripts/site.js
extra:
  social:
  - icon: fontawesome/brands/github
    link: https://github.com/Abdess/retrobios
    name: RetroBIOS on GitHub
markdown_extensions:
- abbr
- admonition
- attr_list
- def_list
- footnotes
- meta
- md_in_html
- tables
- toc:
    permalink: true
- pymdownx.details
- pymdownx.highlight:
    anchor_linenums: true
- pymdownx.inlinehilite
- pymdownx.keys
- pymdownx.superfences:
    custom_fences:
    - name: mermaid
      class: mermaid
      format: !!python/name:pymdownx.superfences.fence_code_format
- pymdownx.tabbed:
    alternate_style: true
plugins:
- search
# Link rot fails the build: deploy-site.yml runs `mkdocs build --strict`.
# omitted_files stays at its default (info) so a stale local docs/ does not
# break a local build; CI regenerates docs/ from scratch anyway.
validation:
  absolute_links: warn
  unrecognized_links: warn
  anchors: warn
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
        + sum(
            1 for profile in profiles.values()
            if profile.get("type") not in ("alias", "test")
        )  # emulator detail pages (aliases/tests remain metadata-only)
        + 1  # gap analysis
        + 1  # which-pack
        + len(list(Path("wiki").glob("*.md")))  # wiki pages copied verbatim
        + 1  # generated wiki/data-model
        + 1  # contributing
        + 1  # data and API
    )
    print(f"\nGenerated {total_pages} pages in {args.docs_dir}/")


if __name__ == "__main__":
    main()
