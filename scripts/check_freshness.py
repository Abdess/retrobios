#!/usr/bin/env python3
"""Confront every transcribed layer with what its upstream serves today.

Each layer the repository transcribes moves on its own schedule: platform
lists, hardware targets, core-info, buildbot system assets, dump catalogs,
romset DATs, the CI toolchain. This script asks each of them the same
question, is the local copy the one upstream serves, and answers with one
row per subject.

Platform and target files are re-scraped through the scrapers' own write path
into a throwaway copy, then diffed against the committed file. The diff
decides, not a version string: a scraper that pins a new tag but produces
the same entries is reported as a version change and nothing else.

The native export patches each platform's own file, kept in a local cache.
That cache is checked against the platform file it was transcribed with: an
original cached before the last rescrape, or under another pin, is no longer
the file our data describes.

Emulator profiles are covered by profile_sync, which is slow (one API pass
per profile). ``--profiles`` runs it here and folds its verdict in.

Usage:
    python scripts/check_freshness.py
    python scripts/check_freshness.py --only platforms,targets
    python scripts/check_freshness.py --json
    python scripts/check_freshness.py --profiles
    python scripts/check_freshness.py --offline      # local age checks only
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import export_native  # noqa: E402
import refresh_data_dirs  # noqa: E402
import upstream  # noqa: E402
from common import (  # noqa: E402
    list_registered_platforms,
    load_emulator_profiles,
    upstream_profile_index,
    yaml_load,
)
from exporter import discover_exporters  # noqa: E402
from exporter.baseline import build_native_model  # noqa: E402
from scripts.scraper.redump_dat_scraper import fetch_snapshot  # noqa: E402
from scripts.scraper.targets import discover_target_scrapers  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_INFO_REPO = "https://github.com/libretro/libretro-core-info"
NO_INTRO_MIRROR = "https://github.com/hugo19941994/auto-datfile-generator"
NO_INTRO_RELEASE = "Daily_Rebuild"
NO_INTRO_ASSET = "no-intro.zip"
TOSEC_DOWNLOADS = "https://www.tosecdev.org/downloads"
MAME_REPO = "https://github.com/mamedev/mame"
FBNEO_REPO = "https://github.com/libretro/FBNeo"
PYPI_URL = "https://pypi.org/pypi/{name}/json"
INSTALLERS = ("install.sh", "install.ps1")

SHOWN_ITEMS = 4  # items named in a diff summary before ", ..."
SHOWN_NAMES = 12  # core names named in an unresolved row before ", ..."
AREAS = ("platforms", "native", "targets", "coreinfo", "data", "catalogs", "ci", "profiles")
OK, STALE, UNKNOWN, ERROR, SKIPPED = "OK", "STALE", "UNKNOWN", "ERROR", "SKIPPED"
# Every status a finding may carry, in the order the summary counts them.
STATUSES = (STALE, UNKNOWN, ERROR, SKIPPED, OK)


@dataclass(frozen=True)
class Finding:
    area: str
    subject: str
    status: str
    local: str = ""
    remote: str = ""
    detail: str = ""


@dataclass
class PlatformDiff:
    """What a fresh scrape changes in a platform or target file."""

    version: tuple[str, str] | None = None
    systems_added: list[str] = field(default_factory=list)
    systems_removed: list[str] = field(default_factory=list)
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    cores_added: list[str] = field(default_factory=list)
    cores_removed: list[str] = field(default_factory=list)

    @property
    def content_changed(self) -> bool:
        return any(
            (
                self.systems_added,
                self.systems_removed,
                self.files_added,
                self.files_removed,
                self.files_changed,
                self.cores_added,
                self.cores_removed,
            )
        )

    @property
    def changed(self) -> bool:
        return self.content_changed or self.version is not None

    def summary(self) -> str:
        parts: list[str] = []
        if self.version:
            parts.append(f"version {self.version[0]} -> {self.version[1]}")
        for label, items in (
            ("+systems", self.systems_added),
            ("-systems", self.systems_removed),
            ("+files", self.files_added),
            ("-files", self.files_removed),
            ("~files", self.files_changed),
            ("+cores", self.cores_added),
            ("-cores", self.cores_removed),
        ):
            if items:
                shown = ", ".join(items[:SHOWN_ITEMS]) + (", ..." if len(items) > SHOWN_ITEMS else "")
                parts.append(f"{label} {len(items)} ({shown})")
        return "; ".join(parts) if parts else "identical"


# --- platforms --------------------------------------------------------------


def _file_key(entry: dict) -> str:
    return str(entry.get("destination") or entry.get("name") or "")


def _core_names(config: dict) -> set[str]:
    cores = config.get("cores")
    names = set(map(str, cores)) if isinstance(cores, list) else set()
    standalone = config.get("standalone_cores")
    if isinstance(standalone, list):
        names.update(f"standalone:{c}" for c in standalone)
    return names


def _keyed_files(files: list[dict]) -> dict[str, dict]:
    """Each declaration under its own key.

    A platform declares one destination several times (an archive once per
    inner ROM, MD5 alternatives): keyed by destination alone, the dict kept
    the last and a change to the others read as identical.
    """
    keyed: dict[str, dict] = {}
    seen: dict[str, int] = {}
    for f in files:
        key = _file_key(f)
        seen[key] = seen.get(key, 0) + 1
        keyed[key if seen[key] == 1 else f"{key}#{seen[key]}"] = f
    return keyed


def diff_platform(old: dict, new: dict) -> PlatformDiff:
    """Compare two platform files the way a reviewer reads the diff.

    Files are keyed by system and destination, so a hash or flag change on
    an existing destination is a change, not a removal plus an addition.
    """
    diff = PlatformDiff()
    old_version, new_version = str(old.get("version", "")), str(new.get("version", ""))
    if old_version != new_version:
        diff.version = (old_version, new_version)
    old_systems = old.get("systems") or {}
    new_systems = new.get("systems") or {}
    diff.systems_added = sorted(set(new_systems) - set(old_systems))
    diff.systems_removed = sorted(set(old_systems) - set(new_systems))
    for system in sorted(set(old_systems) & set(new_systems)):
        old_files = _keyed_files((old_systems[system] or {}).get("files") or [])
        new_files = _keyed_files((new_systems[system] or {}).get("files") or [])
        diff.files_added.extend(
            f"{system}/{k}" for k in sorted(set(new_files) - set(old_files))
        )
        diff.files_removed.extend(
            f"{system}/{k}" for k in sorted(set(old_files) - set(new_files))
        )
        diff.files_changed.extend(
            f"{system}/{k}"
            for k in sorted(set(old_files) & set(new_files))
            if old_files[k] != new_files[k]
        )
    old_cores, new_cores = _core_names(old), _core_names(new)
    diff.cores_added = sorted(new_cores - old_cores)
    diff.cores_removed = sorted(old_cores - new_cores)
    return diff


def diff_targets(old: dict, new: dict) -> PlatformDiff:
    """Compare two target files. The scrape stamp is not a change."""
    diff = PlatformDiff()
    old_targets = old.get("targets") or {}
    new_targets = new.get("targets") or {}
    diff.systems_added = sorted(set(new_targets) - set(old_targets))
    diff.systems_removed = sorted(set(old_targets) - set(new_targets))
    for name in sorted(set(old_targets) & set(new_targets)):
        before = set(map(str, (old_targets[name] or {}).get("cores") or []))
        after = set(map(str, (new_targets[name] or {}).get("cores") or []))
        diff.cores_added.extend(f"{name}/{c}" for c in sorted(after - before))
        diff.cores_removed.extend(f"{name}/{c}" for c in sorted(before - after))
    return diff


def _scrape_into_copy(
    module: str, source: Path, workdir: Path, timeout: int = 900
) -> tuple[Path, str | None]:
    """Run a scraper's own write path on a throwaway copy of *source*.

    The CLI merges into the file it writes, so the copy carries every field
    the scraper preserves and the diff shows only what the scrape changes.
    """
    target = workdir / source.name
    shutil.copyfile(source, target)
    proc = subprocess.run(
        [sys.executable, "-m", module, "-o", str(target)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:]
        return target, tail[0] if tail else f"exit {proc.returncode}"
    return target, None


def _scrapable_platforms(platforms_dir: Path) -> list[tuple[str, str, Path]]:
    """(platform, scraper module, file) for every registered platform.

    A platform that only inherits another and declares no source of its own
    (Lakka) has nothing to scrape: its scraper writes the parent's file.
    """
    with (platforms_dir / "_registry.yml").open(encoding="utf-8") as fh:
        registry = (yaml_load(fh) or {}).get("platforms") or {}
    rows = []
    for name in list_registered_platforms(str(platforms_dir), include_archived=True):
        path = platforms_dir / f"{name}.yml"
        if not path.is_file():
            continue
        with path.open(encoding="utf-8") as fh:
            config = yaml_load(fh) or {}
        scraper = (registry.get(name) or {}).get("scraper")
        if not scraper or (config.get("inherits") and not config.get("source")):
            continue
        rows.append((name, f"scripts.scraper.{scraper}_scraper", path))
    return rows


def check_platforms(platforms_dir: Path, workdir: Path, jobs: int) -> list[Finding]:
    rows = _scrapable_platforms(platforms_dir)
    findings: list[Finding] = []

    def run(row: tuple[str, str, Path]) -> Finding:
        name, module, path = row
        try:
            fresh, error = _scrape_into_copy(module, path, workdir)
        except subprocess.TimeoutExpired:
            return Finding("platforms", name, ERROR, detail="scraper timed out")
        if error:
            return Finding("platforms", name, ERROR, detail=error)
        with path.open(encoding="utf-8") as fh:
            old = yaml_load(fh) or {}
        with fresh.open(encoding="utf-8") as fh:
            new = yaml_load(fh) or {}
        diff = diff_platform(old, new)
        status = STALE if diff.changed else OK
        return Finding(
            "platforms",
            name,
            status,
            local=str(old.get("version", "")),
            remote=str(new.get("version", "")),
            detail=diff.summary(),
        )

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        findings.extend(pool.map(run, rows))
    return sorted(findings, key=lambda f: f.subject)


# --- native originals --------------------------------------------------------


def native_cache_state(
    wanted: dict[str, str],
    root: Path,
    recorded: dict[str, str],
    index: Path,
    transcribed_at: float,
) -> str:
    """Why a platform's cached originals cannot be patched, '' when they can.

    The export corrects the file our data was transcribed from. A cached
    original is that file only if it came from the URL the platform file
    names today and was fetched no earlier than the platform file was last
    rewritten: a branch URL keeps its name while its content moves.
    """
    for relative, url in sorted(wanted.items()):
        path = root / relative
        if not path.is_file():
            return f"{relative} not cached"
        known = recorded.get(export_native.source_key(path, index))
        if known is None:
            return f"{relative} cached from an unrecorded URL"
        if known != url:
            return f"{relative} cached from another revision"
        if path.stat().st_mtime < transcribed_at:
            return f"{relative} cached before the platform file was rewritten"
    return ""


def _transcribed_at(platforms_dir: Path, platform: str) -> float:
    """Last rewrite of the platform file or of any file it inherits."""
    newest = 0.0
    seen: set[str] = set()
    name: str | None = platform
    while name and name not in seen:
        seen.add(name)
        path = platforms_dir / f"{name}.yml"
        if not path.is_file():
            break
        newest = max(newest, path.stat().st_mtime)
        with path.open(encoding="utf-8") as fh:
            name = (yaml_load(fh) or {}).get("inherits")
    return newest


def check_native(platforms_dir: Path, cache_dir: Path, truth_dir: Path) -> list[Finding]:
    exporters = discover_exporters()
    index = cache_dir / export_native.SOURCES_INDEX
    recorded = export_native.load_sources(cache_dir)
    findings: list[Finding] = []
    for name in list_registered_platforms(str(platforms_dir), include_archived=True):
        exporter_class = exporters.get(name)
        if not exporter_class:
            continue
        truth, scraped = export_native.load_inputs(name, truth_dir, str(platforms_dir))
        systems, _ = build_native_model(truth or {}, scraped)
        wanted = export_native.wanted_sources(exporter_class(), systems, scraped)
        reason = native_cache_state(
            wanted, cache_dir / name, recorded, index, _transcribed_at(platforms_dir, name)
        )
        findings.append(
            Finding(
                "native",
                name,
                STALE if reason else OK,
                local=f"{len(wanted)} file(s)",
                detail=f"{reason}, export_native.py --refresh-cache fetches it" if reason else "",
            )
        )
    return sorted(findings, key=lambda f: f.subject)


# --- targets ----------------------------------------------------------------


def profile_name_index(profiles: dict[str, dict]) -> dict[str, set[str]]:
    """Upstream core name -> the profiles that claim it, as target filtering reads it."""
    return upstream_profile_index(profiles, include_aliases=True)


def _removed_cores(overrides: dict, platform: str) -> dict[str, set[str]]:
    targets = ((overrides.get(platform) or {}).get("targets")) or {}
    default = set(map(str, (targets.get("_default") or {}).get("remove_cores") or []))
    return {
        name: default | set(map(str, (entry or {}).get("remove_cores") or []))
        for name, entry in targets.items()
        if name != "_default"
    } | {"_default": default}


def unresolved_target_cores(
    targets: dict, index: dict[str, str], removed: dict[str, set[str]]
) -> dict[str, list[str]]:
    """Core names a target lists that no profile claims and no override drops."""
    unresolved: dict[str, list[str]] = {}
    default_drop = removed.get("_default", set())
    for name, entry in (targets.get("targets") or {}).items():
        dropped = removed.get(name, default_drop) | default_drop
        for core in map(str, (entry or {}).get("cores") or []):
            if core not in index and core not in dropped:
                unresolved.setdefault(core, []).append(name)
    return {core: sorted(names) for core, names in sorted(unresolved.items())}


def _target_scrapers() -> dict[str, str]:
    """platform -> scraper module for every target scraper on disk."""
    return {
        platform: cls.__module__
        for platform, cls in discover_target_scrapers().items()
    }


def check_targets(
    platforms_dir: Path, workdir: Path, profiles: dict[str, dict], jobs: int,
    offline: bool,
) -> list[Finding]:
    targets_dir = platforms_dir / "targets"
    overrides_path = targets_dir / "_overrides.yml"
    overrides = {}
    if overrides_path.is_file():
        with overrides_path.open(encoding="utf-8") as fh:
            overrides = yaml_load(fh) or {}
    index = profile_name_index(profiles)
    scrapers = {} if offline else _target_scrapers()
    findings: list[Finding] = []
    today = datetime.now(timezone.utc)

    def run(platform: str) -> list[Finding]:
        path = targets_dir / f"{platform}.yml"
        if not path.is_file():
            return [Finding("targets", platform, ERROR, detail="no target file")]
        with path.open(encoding="utf-8") as fh:
            old = yaml_load(fh) or {}
        module = scrapers.get(platform)
        if module is None:
            # No scraper: a hand-written file has no upstream to diff against,
            # so only its age and its core names can be reported.
            stamp = str(old.get("scraped_at", ""))[:10]
            age = _age_days(stamp, today)
            out = [
                Finding(
                    "targets",
                    platform,
                    OK if age is not None else UNKNOWN,
                    local=f"static {stamp}",
                    detail=f"{age} days old" if age is not None else "no scrape stamp",
                )
            ]
            missing = unresolved_target_cores(old, index, _removed_cores(overrides, platform))
            out.extend(_unresolved_findings(platform, missing))
            return out
        try:
            fresh, error = _scrape_into_copy(module, path, workdir)
        except subprocess.TimeoutExpired:
            return [Finding("targets", platform, ERROR, detail="scraper timed out")]
        if error:
            return [Finding("targets", platform, ERROR, detail=error)]
        with fresh.open(encoding="utf-8") as fh:
            new = yaml_load(fh) or {}
        diff = diff_targets(old, new)
        out = [
            Finding(
                "targets",
                platform,
                STALE if diff.content_changed else OK,
                local=str(old.get("scraped_at", ""))[:10],
                remote=str(new.get("scraped_at", ""))[:10],
                detail=diff.summary(),
            )
        ]
        missing = unresolved_target_cores(new, index, _removed_cores(overrides, platform))
        out.extend(_unresolved_findings(platform, missing))
        return out

    names = sorted(p.stem for p in targets_dir.glob("*.yml") if not p.name.startswith("_"))
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for rows in pool.map(run, names):
            findings.extend(rows)
    return findings


def _unresolved_findings(platform: str, missing: dict[str, list[str]]) -> list[Finding]:
    """One row per platform: the names its targets list that no profile claims.

    A buildbot name without a profile is a core the target filter cannot
    see; a platform's own emulator id without one is an emulator nobody has
    profiled yet. Both are actionable, so both are listed, but as one row so
    the backlog does not bury the day's changes.
    """
    if not missing:
        return []
    names = sorted(missing)
    shown = ", ".join(names[:SHOWN_NAMES]) + (", ..." if len(names) > SHOWN_NAMES else "")
    return [
        Finding(
            "targets",
            f"{platform} cores",
            STALE,
            local=f"{len(names)} without a profile",
            detail=f"cores: alias or _overrides remove_cores needed for {shown}",
        )
    ]


def _age_days(stamp: str, now: datetime) -> int | None:
    try:
        then = datetime.strptime(stamp[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (now - then).days


# --- core-info --------------------------------------------------------------


def core_info_names(cache_dir: str, offline: bool) -> list[str] | None:
    """Every core the libretro core-info repository describes."""
    repo = upstream.parse_repo(CORE_INFO_REPO)
    if repo is None:
        return None
    payload = upstream._api(  # noqa: SLF001
        f"{repo.api_base}/repos/{repo.slug}/contents?per_page=100",
        cache_dir,
        offline,
        upstream.MOVING_TTL,
    )
    if not isinstance(payload, list):
        return None
    names = []
    for entry in payload:
        name = entry.get("name", "") if isinstance(entry, dict) else ""
        if name.endswith("_libretro.info"):
            names.append(name[: -len("_libretro.info")])
    return sorted(names)


def coreinfo_gaps(
    names: list[str], profiles: dict[str, dict]
) -> tuple[list[str], list[tuple[str, str]]]:
    """Cores core-info knows that the profiles do not, and profiles that
    call standalone a core libretro now builds.

    Matching folds case: the buildbot serves lower-case names while a few
    .info files keep the project's own casing.
    """
    index: dict[str, set[str]] = {}
    for key, claimants in profile_name_index(profiles).items():
        index.setdefault(key.casefold(), set()).update(claimants)
    unprofiled = [n for n in names if n.casefold() not in index]
    # A name only standalone profiles claim: libretro now builds a core
    # nothing in the collection describes as one.
    standalone = [
        (n, sorted(index[n.casefold()])[0])
        for n in names
        if n.casefold() in index
        and all(
            str(profiles[c].get("type", "")).strip() == "standalone"
            for c in index[n.casefold()]
        )
    ]
    return unprofiled, standalone


def check_coreinfo(profiles: dict[str, dict], cache_dir: str, offline: bool) -> list[Finding]:
    names = core_info_names(cache_dir, offline)
    if names is None:
        return [Finding("coreinfo", "libretro-core-info", UNKNOWN, detail="listing unavailable")]
    unprofiled, standalone = coreinfo_gaps(names, profiles)
    findings = [
        Finding(
            "coreinfo",
            "libretro-core-info",
            STALE if unprofiled or standalone else OK,
            local=f"{len(names) - len(unprofiled)} profiled",
            remote=f"{len(names)} .info files",
        )
    ]
    findings.extend(
        Finding("coreinfo", name, STALE, detail="no profile claims this core name")
        for name in unprofiled
    )
    findings.extend(
        Finding(
            "coreinfo",
            name,
            STALE,
            local=f"{key}: type standalone",
            detail="core-info describes a libretro build of it",
        )
        for name, key in standalone
    )
    return findings


# --- data directories -------------------------------------------------------


def check_data(offline: bool) -> list[Finding]:
    if offline:
        return [Finding("data", "_data_dirs.yml", SKIPPED, detail="offline")]
    registry = refresh_data_dirs.load_registry(str(REPO_ROOT / "platforms" / "_data_dirs.yml"))
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        results = refresh_data_dirs.refresh_all(registry, dry_run=True)
    findings = []
    for key, result in sorted(results.items()):
        if result is None:
            findings.append(Finding("data", key, UNKNOWN, detail="remote unreachable"))
        elif result:
            findings.append(Finding("data", key, STALE, detail="upstream changed, refresh_data_dirs.py fetches it"))
        else:
            findings.append(Finding("data", key, OK))
    return findings


# --- catalogs and recipes ---------------------------------------------------


def _snapshot(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def check_catalogs(cache_dir: str, offline: bool) -> list[Finding]:
    findings = []
    findings.append(_check_redump(offline))
    findings.append(_check_no_intro(cache_dir, offline))
    findings.append(_check_tosec(offline))
    findings.append(_check_mame(cache_dir, offline))
    findings.append(_check_fbneo(cache_dir, offline))
    return findings


def _check_redump(offline: bool) -> Finding:
    local = _snapshot(REPO_ROOT / "provenance" / "redump.json")
    dats = local.get("dats") or {}
    stamp = ", ".join(sorted(set(dats.values()))) or "none"
    if offline:
        return Finding("catalogs", "redump", SKIPPED, local=stamp, detail="offline")
    try:
        remote_dats, _ = fetch_snapshot()
    except (ConnectionError, ValueError) as exc:
        return Finding("catalogs", "redump", UNKNOWN, local=stamp, detail=str(exc))
    remote_stamp = ", ".join(sorted(set(remote_dats.values())))
    changed = sorted(
        name for name in set(dats) | set(remote_dats) if dats.get(name) != remote_dats.get(name)
    )
    return Finding(
        "catalogs",
        "redump",
        STALE if changed else OK,
        local=stamp,
        remote=remote_stamp,
        detail=("changed: " + ", ".join(changed)) if changed else f"{len(dats)} DATs",
    )


def _check_no_intro(cache_dir: str, offline: bool) -> Finding:
    local = _snapshot(REPO_ROOT / "provenance" / "no-intro.json")
    imported = str(local.get("imported_at", ""))
    if offline:
        return Finding("catalogs", "no-intro", SKIPPED, local=imported, detail="offline")
    repo = upstream.parse_repo(NO_INTRO_MIRROR)
    payload = upstream._api(  # noqa: SLF001
        f"{repo.api_base}/repos/{repo.slug}/releases/tags/{NO_INTRO_RELEASE}",
        cache_dir,
        offline,
        upstream.MOVING_TTL,
    )
    assets = payload.get("assets") if isinstance(payload, dict) else None
    updated = ""
    for asset in assets or []:
        if isinstance(asset, dict) and asset.get("name") == NO_INTRO_ASSET:
            updated = str(asset.get("updated_at", ""))[:10]
    if not updated:
        return Finding("catalogs", "no-intro", UNKNOWN, local=imported, detail="asset not listed")
    return Finding(
        "catalogs",
        "no-intro",
        STALE if updated > imported else OK,
        local=imported,
        remote=updated,
        detail=f"{NO_INTRO_ASSET} rebuilt {updated}",
    )


def tosec_latest_pack(html: str) -> str | None:
    """Date of the newest TOSEC release the downloads page lists."""
    dates = re.findall(r'/downloads/category/\d+-(\d{4}-\d{2}-\d{2})"', html)
    return max(dates) if dates else None


def _check_tosec(offline: bool) -> Finding:
    local = _snapshot(REPO_ROOT / "provenance" / "tosec.json")
    imported = str(local.get("imported_at", ""))
    if offline:
        return Finding("catalogs", "tosec", SKIPPED, local=imported, detail="offline")
    try:
        html = upstream._http_text(TOSEC_DOWNLOADS)  # noqa: SLF001
    except upstream.UpstreamError as exc:
        return Finding("catalogs", "tosec", UNKNOWN, local=imported, detail=str(exc))
    latest = tosec_latest_pack(html or "")
    if latest is None:
        return Finding("catalogs", "tosec", UNKNOWN, local=imported, detail="no release listed")
    return Finding(
        "catalogs",
        "tosec",
        STALE if latest > imported else OK,
        local=imported,
        remote=latest,
        detail=f"newest pack TOSEC-v{latest}",
    )


def mame_versions(recipes: dict) -> list[str]:
    """MAME version tags a recipe snapshot has absorbed, oldest first."""
    tags = set()
    for label in (recipes.get("dats") or {}):
        match = re.search(r"\b(mame\d{4})\b", str(label))
        if match:
            tags.add(match.group(1))
    return sorted(tags)


def _check_mame(cache_dir: str, offline: bool) -> Finding:
    local = _snapshot(REPO_ROOT / "recipes" / "mame.json")
    versions = mame_versions(local)
    newest = versions[-1] if versions else "none"
    if offline:
        return Finding("catalogs", "mame recipes", SKIPPED, local=newest, detail="offline")
    release = upstream.latest_release(upstream.parse_repo(MAME_REPO), cache_dir, offline)
    if release is None:
        return Finding("catalogs", "mame recipes", UNKNOWN, local=newest, detail="no release seen")
    return Finding(
        "catalogs",
        "mame recipes",
        OK if release.tag in versions else STALE,
        local=newest,
        remote=f"{release.tag} ({release.date})",
        detail=f"{len(versions)} versions imported",
    )


def fbneo_blob_drift(snapshot: dict, listing: object) -> tuple[list[str], bool]:
    """DAT files whose git blob differs from the one the snapshot was read
    from. The second value says whether the snapshot records blobs at all:
    one written before that field existed can only be compared by date.
    """
    recorded = (snapshot.get("upstream") or {}).get("blobs") or {}
    if not recorded:
        return [], False
    remote = {
        item["name"]: item.get("sha", "")
        for item in (listing if isinstance(listing, list) else [])
        if isinstance(item, dict)
        and item.get("type") == "file"
        and str(item.get("name", "")).lower().endswith(".dat")
    }
    drifted = sorted(
        name for name in set(recorded) | set(remote) if recorded.get(name) != remote.get(name)
    )
    return drifted, True


def _check_fbneo(cache_dir: str, offline: bool) -> Finding:
    local = _snapshot(REPO_ROOT / "recipes" / "fbneo.json")
    imported = str(local.get("imported_at", ""))
    if offline:
        return Finding("catalogs", "fbneo recipes", SKIPPED, local=imported, detail="offline")
    repo = upstream.parse_repo(FBNEO_REPO)
    listing = upstream._api(  # noqa: SLF001
        f"{repo.api_base}/repos/{repo.slug}/contents/dats",
        cache_dir,
        offline,
        upstream.MOVING_TTL,
    )
    if not isinstance(listing, list):
        return Finding("catalogs", "fbneo recipes", UNKNOWN, local=imported, detail="dats/ listing unavailable")
    drifted, tracked = fbneo_blob_drift(local, listing)
    if not tracked:
        return Finding(
            "catalogs",
            "fbneo recipes",
            STALE,
            local=imported,
            detail="snapshot records no upstream blobs: re-import with --fetch",
        )
    shown = ", ".join(n.removeprefix("FinalBurn Neo (ClrMame Pro XML, ").removesuffix(" only).dat") for n in drifted[:4])
    return Finding(
        "catalogs",
        "fbneo recipes",
        STALE if drifted else OK,
        local=imported,
        remote=f"{len(listing)} DATs listed",
        detail=(f"{len(drifted)} DAT(s) changed upstream: {shown}" if drifted else "every DAT blob matches"),
    )


# --- CI toolchain -----------------------------------------------------------

_PIN_RE = re.compile(
    r'"?([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?((?:[<>=!~]=?[^,"\s]+)(?:,[<>=!~]=?[^,"\s]+)*)?"?'
)
_USES_RE = re.compile(r"uses:\s*([\w.\-]+/[\w.\-]+)@([0-9a-f]{40})\s*(?:#\s*(\S+))?")


def parse_pip_pins(text: str) -> dict[str, str]:
    """Package -> specifier for every ``pip install`` line of a workflow."""
    pins: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if "pip install" not in stripped:
            continue
        args = stripped.split("pip install", 1)[1]
        for raw in re.findall(r'"[^"]+"|\S+', args):
            token = raw.strip('"')
            if token.startswith("-") or not token:
                continue
            match = _PIN_RE.fullmatch(token)
            if match:
                pins.setdefault(match.group(1).lower(), match.group(2) or "")
    return pins


def parse_action_pins(text: str) -> dict[str, tuple[str, str]]:
    """Action -> (pinned sha, commented tag) for every ``uses:`` line."""
    return {
        repo: (sha, tag or "") for repo, sha, tag in _USES_RE.findall(text)
    }


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


_SPEC_CLAUSE = re.compile(r"([<>=!~]=?)\s*(.+)")
_SPEC_TESTS = {
    "==": lambda target, bound: target == bound,
    "!=": lambda target, bound: target != bound,
    ">=": lambda target, bound: target >= bound,
    ">": lambda target, bound: target > bound,
    "<=": lambda target, bound: target <= bound,
    "<": lambda target, bound: target < bound,
}


def specifier_allows(spec: str, version: str) -> bool:
    """Whether a pip specifier admits a version. Pre-releases are compared
    on their numeric parts, which is enough for the operators pip uses here."""
    target = _version_tuple(version)
    for clause in filter(None, (c.strip() for c in spec.split(","))):
        match = _SPEC_CLAUSE.fullmatch(clause)
        test = _SPEC_TESTS.get(match.group(1)) if match else None
        if test is None or not test(target, _version_tuple(match.group(2))):
            return False
    return True


def pypi_latest(name: str) -> str | None:
    payload = upstream._http_json(PYPI_URL.format(name=name))  # noqa: SLF001
    if not isinstance(payload, dict):
        return None
    info = payload.get("info") or {}
    return str(info.get("version") or "") or None


def check_ci(cache_dir: str, offline: bool) -> list[Finding]:
    findings = [_check_installer_pins()]
    workflows = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    pins: dict[str, str] = {}
    actions: dict[str, tuple[str, str]] = {}
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        for name, spec in parse_pip_pins(text).items():
            pins.setdefault(name, spec)
        actions.update(parse_action_pins(text))
    if offline:
        findings.append(Finding("ci", "workflow pins", SKIPPED, detail="offline"))
        return findings
    for name, spec in sorted(pins.items()):
        try:
            latest = pypi_latest(name)
        except upstream.UpstreamError as exc:
            findings.append(Finding("ci", f"pypi:{name}", UNKNOWN, local=spec, detail=str(exc)))
            continue
        if latest is None:
            findings.append(Finding("ci", f"pypi:{name}", UNKNOWN, local=spec, detail="not on PyPI"))
            continue
        allowed = specifier_allows(spec, latest)
        findings.append(
            Finding(
                "ci",
                f"pypi:{name}",
                OK if allowed else STALE,
                local=spec or "unpinned",
                remote=latest,
                detail="latest admitted" if allowed else "latest release outside the pin",
            )
        )
    for action, (sha, tag) in sorted(actions.items()):
        repo = upstream.parse_repo(f"https://github.com/{action}")
        release = upstream.latest_release(repo, cache_dir, offline)
        if release is None:
            findings.append(Finding("ci", f"action:{action}", UNKNOWN, local=f"{sha[:8]} {tag}", detail="no release seen"))
            continue
        latest_sha = upstream.tag_commit(repo, release.tag, cache_dir, offline) or ""
        findings.append(
            Finding(
                "ci",
                f"action:{action}",
                OK if latest_sha == sha else STALE,
                local=f"{sha[:8]} {tag}".strip(),
                remote=f"{latest_sha[:8]} {release.tag}",
                detail="" if latest_sha == sha else f"{release.tag} released {release.date}",
            )
        )
    return findings


def _check_installer_pins() -> Finding:
    """The bootstraps pin install.py by SHA-256; a stale pin refuses every install."""
    digest = hashlib.sha256((REPO_ROOT / "install.py").read_bytes()).hexdigest()
    stale = []
    for name in INSTALLERS:
        text = (REPO_ROOT / name).read_text(encoding="utf-8", errors="replace")
        if digest not in text:
            stale.append(name)
    return Finding(
        "ci",
        "install.py pin",
        STALE if stale else OK,
        local=digest[:12],
        detail=("pin outdated in " + ", ".join(stale)) if stale else "install.sh and install.ps1 match",
    )


# --- profiles ---------------------------------------------------------------


def check_profiles(run: bool, offline: bool) -> list[Finding]:
    if not run:
        return [
            Finding(
                "profiles",
                "profile_sync",
                SKIPPED,
                detail="pass --profiles, or run profile_sync.py --all --triage",
            )
        ]
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "profile_sync.py"),
        "--all",
        "--json",
        "--check-version",
        "--detect-new-files",
        "--watch-hashes",
    ]
    if offline:
        cmd.append("--offline")
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        tail = proc.stderr.strip().splitlines()[-1:]
        return [Finding("profiles", "profile_sync", ERROR, detail=tail[0] if tail else f"exit {proc.returncode}")]
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return [Finding("profiles", "profile_sync", ERROR, detail=f"unreadable report: {exc}")]
    return summarize_profile_sync(report)


def summarize_profile_sync(report: object) -> list[Finding]:
    """One row per profile with something to look at, from profile_sync's JSON.

    The JSON carries the ref verdicts and the pin against the tip; a profile
    whose refs need review is stale, one the forge could not serve is unknown,
    and one whose upstream moved while every ref still anchors is reported as
    such without being counted as stale.
    """
    if not isinstance(report, list):
        return [Finding("profiles", "profile_sync", ERROR, detail="report is not a list")]
    findings = []
    clean = moved = 0
    for row in report:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "?")
        if row.get("skipped"):
            findings.append(Finding("profiles", name, UNKNOWN, detail=str(row["skipped"])))
            continue
        review = row.get("needs_review") or 0
        pin, head = str(row.get("pin") or ""), str(row.get("head") or "")
        if review:
            findings.append(
                Finding(
                    "profiles",
                    name,
                    STALE,
                    local=pin[:8],
                    remote=head[:8],
                    detail=f"{review} refs to review",
                )
            )
        elif pin and head and pin != head:
            moved += 1
        else:
            clean += 1
    stale = sum(1 for f in findings if f.status == STALE)
    findings.insert(
        0,
        Finding(
            "profiles",
            "profile_sync",
            STALE if stale else OK,
            local=f"{clean} at tip, {moved} anchored past the tip",
            remote=f"{stale} to review",
        ),
    )
    return findings


# --- reporting --------------------------------------------------------------


def render(findings: list[Finding]) -> str:
    lines = []
    width = max((len(f.subject) for f in findings), default=10)
    width = min(width, 44)
    for area in AREAS:
        rows = [f for f in findings if f.area == area]
        if not rows:
            continue
        lines.append(f"\n[{area}]")
        for f in rows:
            cols = f"  {f.status:7} {f.subject[:width]:{width}}"
            if f.local or f.remote:
                cols += f"  {f.local[:32]:32} -> {f.remote[:32]}"
            if f.detail:
                cols += f"  {f.detail}"
            lines.append(cols.rstrip())
    counts = {status: sum(1 for f in findings if f.status == status) for status in STATUSES}
    summary = ", ".join(f"{n} {status.lower()}" for status, n in counts.items() if n)
    lines.append(f"\nFRESHNESS: {summary}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", help="comma-separated areas: " + ",".join(AREAS))
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--profiles", action="store_true", help="also run profile_sync (slow)")
    parser.add_argument("--offline", action="store_true", help="no network, local ages only")
    parser.add_argument("--jobs", type=int, default=4, help="parallel scrapers")
    parser.add_argument("--cache-dir", default=upstream.CACHE_DIR)
    parser.add_argument("--native-cache-dir", default=export_native.DEFAULT_CACHE)
    parser.add_argument("--truth-dir", default="dist/truth")
    parser.add_argument("--platforms-dir", default="platforms")
    parser.add_argument("--emulators-dir", default="emulators")
    args = parser.parse_args()

    areas = tuple(a.strip() for a in args.only.split(",")) if args.only else AREAS
    unknown = sorted(set(areas) - set(AREAS))
    if unknown:
        parser.error(f"unknown area: {', '.join(unknown)}")

    platforms_dir = Path(args.platforms_dir)
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="freshness-", dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir() else None) as scratch:
        workdir = Path(scratch)
        if "platforms" in areas:
            findings.extend(
                [Finding("platforms", "scrapers", SKIPPED, detail="offline")]
                if args.offline
                else check_platforms(platforms_dir, workdir, args.jobs)
            )
        if "native" in areas:
            findings.extend(
                check_native(platforms_dir, Path(args.native_cache_dir), Path(args.truth_dir))
            )
        if "targets" in areas:
            findings.extend(check_targets(platforms_dir, workdir, profiles, args.jobs, args.offline))
    if "coreinfo" in areas:
        findings.extend(check_coreinfo(profiles, args.cache_dir, args.offline))
    if "data" in areas:
        findings.extend(check_data(args.offline))
    if "catalogs" in areas:
        findings.extend(check_catalogs(args.cache_dir, args.offline))
    if "ci" in areas:
        findings.extend(check_ci(args.cache_dir, args.offline))
    if "profiles" in areas:
        findings.extend(check_profiles(args.profiles, args.offline))

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render(findings))
    return 1 if any(f.status in (STALE, ERROR) for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
