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
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import export_native  # noqa: E402
import pin_installer  # noqa: E402
import refresh_data_dirs  # noqa: E402
import upstream  # noqa: E402
from common import (  # noqa: E402
    InputMissing,
    apply_target_overrides,
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_registry,
    require_directory,
    suggest_names,
    upstream_profile_index,
    write_text_atomic,
    yaml_load,
)
from exporter import discover_exporters  # noqa: E402
from exporter.baseline import build_native_model  # noqa: E402
from scripts.scraper import game_dat_importer  # noqa: E402
from scripts.scraper.redump_dat_scraper import fetch_snapshot  # noqa: E402
from scripts.scraper.targets import discover_target_scrapers  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_INFO_REPO = "https://github.com/libretro/libretro-core-info"
# The git blob of every .info as last reviewed: `--record-coreinfo` writes it.
CORE_INFO_RECORD = REPO_ROOT / "platforms" / "_core_info.json"
NO_INTRO_MIRROR = game_dat_importer.NOINTRO_MIRROR
NO_INTRO_RELEASE = game_dat_importer.NOINTRO_RELEASE
NO_INTRO_ASSET = game_dat_importer.NOINTRO_ASSET
# The mirror rebuilds daily. A pack older than this is a mirror that stopped:
# hugo19941994's failed every day from 2026-07-08, and comparing our import
# date with its asset read OK for four months.
NO_INTRO_MAX_AGE_DAYS = 7
TOSEC_DOWNLOADS = "https://www.tosecdev.org/downloads"
MAME_REPO = "https://github.com/mamedev/mame"
FBNEO_REPO = "https://github.com/libretro/FBNeo"
PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_URL = "https://registry.npmjs.org/{name}/latest"
# The site's npm dependencies, pinned to exact versions and built by Deploy Site.
SITE_PACKAGE = REPO_ROOT / "website" / "package.json"

SHOWN_ITEMS = 4  # items named in a diff summary before ", ..."
SHOWN_NAMES = 12  # core names named in an unresolved row before ", ..."
AREAS = (
    "platforms", "native", "targets", "romfolders", "coreinfo", "data", "catalogs", "ci", "profiles",
)
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
    # Every name a shortened detail stands for: --json carries them all, so
    # a script can act on the 50 cores a row names 12 of.
    items: list[str] = field(default_factory=list)


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
    # Any other field the scrape writes: launchers, dual_mode_cores, a
    # system's core, native_id or data_directories.
    fields_changed: list[str] = field(default_factory=list)

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
                self.fields_changed,
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
            ("~fields", self.fields_changed),
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


# Compared on their own above. `source` is the revision read: it moves with
# every upstream commit, and what that commit changes is diffed field by field.
_DIFFED_APART = frozenset({"version", "systems", "cores", "standalone_cores", "source"})


def _without_refs(value: object) -> object:
    """*value* without its `source_ref` lines.

    A launcher cites lines of the revision read, so they shift with any
    upstream commit above them (es_features.cfg:11638 read as :11649 one
    RetroBat commit later). The cited content is what is compared.
    """
    if isinstance(value, dict):
        return {k: _without_refs(v) for k, v in value.items() if k != "source_ref"}
    if isinstance(value, list):
        return [_without_refs(v) for v in value]
    return value


def _changed_fields(old: dict, new: dict, skip: frozenset[str], prefix: str = "") -> list[str]:
    return [
        f"{prefix}{key}"
        for key in sorted(set(old) | set(new), key=str)
        if key not in skip and _without_refs(old.get(key)) != _without_refs(new.get(key))
    ]


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
        diff.fields_changed.extend(_changed_fields(
            old_systems[system] or {}, new_systems[system] or {},
            frozenset({"files"}), f"{system}/",
        ))
    diff.fields_changed = _changed_fields(old, new, _DIFFED_APART) + diff.fields_changed
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
    for name in list_registered_platforms(str(platforms_dir)):
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


_EJS_VERSION_RE = re.compile(r"^ARG EMULATORJS_VERSION=(\S+)", re.MULTILINE)
ROMM_DOCKERFILES = ("docker/Dockerfile", "Dockerfile")


def emulatorjs_pin(dockerfile: str) -> str | None:
    """The EmulatorJS release a RomM image installs, from its Dockerfile."""
    match = _EJS_VERSION_RE.search(dockerfile)
    return match.group(1) if match else None


def check_emulatorjs(platforms_dir: Path, offline: bool) -> Finding:
    """emulatorjs.yml against the EmulatorJS release RomM's image installs.

    emulatorjs.yml is not a registered platform, so no scrape covers it: a
    RomM moving to a newer EmulatorJS changed the cores its users run with
    nothing to say so.
    """
    subject = "romm emulatorjs"
    with (platforms_dir / "emulatorjs.yml").open(encoding="utf-8") as fh:
        local = str((yaml_load(fh) or {}).get("version", ""))
    if offline:
        return Finding("platforms", subject, SKIPPED, local=local, detail="offline")
    with (platforms_dir / "romm.yml").open(encoding="utf-8") as fh:
        tag = str((yaml_load(fh) or {}).get("version", ""))
    for path in ROMM_DOCKERFILES:
        try:
            text = upstream._http_text(
                f"https://raw.githubusercontent.com/rommapp/romm/{tag}/{path}")
        except upstream.UpstreamError as exc:
            return Finding("platforms", subject, UNKNOWN, local=local, detail=str(exc))
        pin = emulatorjs_pin(text or "")
        if pin:
            return Finding("platforms", subject, OK if pin == local else STALE,
                           local=local, remote=pin,
                           detail=f"RomM {tag} installs EmulatorJS {pin}")
    return Finding("platforms", subject, UNKNOWN, local=local,
                   detail=f"no EMULATORJS_VERSION in RomM {tag}'s Dockerfile")


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


def _export_tree(root: Path, platform: str) -> dict[str, bytes]:
    """A platform's published export: its directory and its report."""
    tree = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in (root / platform).rglob("*") if path.is_file()
    }
    report = root / f"{platform}.json"
    if report.is_file():
        tree[report.name] = report.read_bytes()
    return tree


def published_export_state(
    platform: str,
    exporter_class: type,
    truth_dir: Path,
    platforms_dir: Path,
    cache_dir: Path,
    published: Path,
) -> str:
    """Why the committed export is not what the export writes now, '' when it is.

    exports/ is committed and the site publishes it, but CI cannot rebuild
    it: the originals it patches live in the local cache. A profile change
    that moves a hash leaves the published file behind until someone runs
    the export again, and this is what says so.
    """
    scratch_root = Path("tmp")
    scratch_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch_root) as scratch:
        with contextlib.redirect_stdout(io.StringIO()):
            ok, messages = export_native.export_platform(
                platform, exporter_class, truth_dir, Path(scratch),
                str(platforms_dir), cache_dir, False,
            )
        if not ok:
            return f"the export fails: {messages[0] if messages else 'no message'}"
        if _export_tree(Path(scratch), platform) != _export_tree(published, platform):
            return f"{published.as_posix()}/{platform} is not what the export writes now"
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


# How the truth model settles two cores' hashes: generate_truth reports it,
# and it says nothing about whether a cached original is current.
_MODEL_NOTES = ("WARNING: hash conflict",)


@contextlib.contextmanager
def _without_model_notes() -> Iterator[None]:
    """Keep the model build's own notes out of the freshness report.

    Anything else written to stderr passes through.
    """
    sink = io.StringIO()
    try:
        with contextlib.redirect_stderr(sink):
            yield
    finally:
        for line in sink.getvalue().splitlines(keepends=True):
            if not line.startswith(_MODEL_NOTES):
                sys.stderr.write(line)


def check_native(
    platforms_dir: Path, cache_dir: Path, truth_dir: Path,
    published: Path = Path("exports"),
) -> list[Finding]:
    exporters = discover_exporters()
    index = cache_dir / export_native.SOURCES_INDEX
    try:
        recorded = export_native.load_sources(cache_dir)
    except export_native.SourcesIndexUnreadable as exc:
        return [Finding("native", index.name, ERROR, detail=str(exc))]
    findings: list[Finding] = []
    for name in list_registered_platforms(str(platforms_dir)):
        exporter_class = exporters.get(name)
        if not exporter_class:
            continue
        with _without_model_notes():
            try:
                truth, scraped = export_native.load_inputs(name, truth_dir, str(platforms_dir))
            except export_native.StaleTruth as exc:
                findings.append(Finding("native", name, STALE, detail=str(exc)))
                continue
            systems, _ = build_native_model(truth or {}, scraped)
            wanted = export_native.wanted_sources(exporter_class(), systems, scraped)
            reason = native_cache_state(
                wanted, cache_dir / name, recorded, index, _transcribed_at(platforms_dir, name)
            )
            if reason:
                reason += (
                    f", python scripts/export_native.py --platform {name} --refresh-cache"
                    " fetches it, then the export is written again"
                )
            else:
                reason = published_export_state(
                    name, exporter_class, truth_dir, platforms_dir, cache_dir, published
                )
                if reason:
                    reason += f", python scripts/export_native.py --platform {name} writes it again"
        findings.append(
            Finding(
                "native",
                name,
                STALE if reason else OK,
                local=f"{len(wanted)} file(s)",
                detail=reason,
            )
        )
    return sorted(findings, key=lambda f: f.subject)


# --- targets ----------------------------------------------------------------


def profile_name_index(profiles: dict[str, dict]) -> dict[str, set[str]]:
    """Upstream core name -> the profiles that claim it, as target filtering reads it."""
    return upstream_profile_index(profiles, include_aliases=True)


def _platform_overrides(overrides: dict, platform: str) -> dict:
    """The per-target entries of _overrides.yml for one platform."""
    return ((overrides.get(platform) or {}).get("targets")) or {}


def unresolved_target_cores(
    targets: dict, index: dict[str, str], overrides: dict
) -> dict[str, list[str]]:
    """Core names a target ends up with that no profile claims.

    Read after the overrides, by the function the builder applies
    (apply_target_overrides): _default then the target, add_cores
    included. A name added by hand without a profile is the false skip
    this check exists for, and a copy that read remove_cores alone never
    saw it.
    """
    unresolved: dict[str, list[str]] = {}
    for name, entry in (targets.get("targets") or {}).items():
        cores = {str(c) for c in (entry or {}).get("cores") or []}
        for core in sorted(apply_target_overrides(cores, overrides, name)):
            if core not in index:
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
    scrapers = _target_scrapers()
    findings: list[Finding] = []
    today = datetime.now(timezone.utc)

    def run(platform: str) -> list[Finding]:
        path = targets_dir / f"{platform}.yml"
        if not path.is_file():
            return [Finding("targets", platform, ERROR, detail="no target file")]
        with path.open(encoding="utf-8") as fh:
            old = yaml_load(fh) or {}
        module = scrapers.get(platform)
        targets = old.get("targets") or {}
        if module is not None and offline:
            # Scraped, so offline means not compared: SKIPPED, as every other
            # section says it. Labelled static and OK, a list 400 days old
            # read as current.
            stamp = str(old.get("scraped_at", ""))[:10]
            out = [Finding("targets", platform, SKIPPED, local=stamp, detail="offline")]
            missing = unresolved_target_cores(old, index, _platform_overrides(overrides, platform))
            out.extend(_unresolved_findings(platform, missing))
            return out
        if module is None and targets and all(
            (t or {}).get("cores", []) is None for t in targets.values()
        ):
            # Every core the platform declares runs on these targets: the list
            # is the platform's own and has nothing of its own to age. Its
            # names still need a profile each: RetroBat's winuae, jzintv or
            # sudachi without one are BIOS its pack never carries.
            out = [Finding("targets", platform, OK, local="static",
                           detail="every declared core")]
            declared = _declared_cores(platform)
            missing = unresolved_target_cores(
                {"targets": {name: {"cores": declared} for name in targets}},
                index, _platform_overrides(overrides, platform),
            )
            out.extend(_unresolved_findings(platform, missing))
            return out
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
            missing = unresolved_target_cores(old, index, _platform_overrides(overrides, platform))
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
        missing = unresolved_target_cores(new, index, _platform_overrides(overrides, platform))
        out.extend(_unresolved_findings(platform, missing))
        return out

    names = sorted(p.stem for p in targets_dir.glob("*.yml") if not p.name.startswith("_"))
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for rows in pool.map(run, names):
            findings.extend(rows)
    return findings


def _declared_cores(platform: str) -> list[str]:
    """The cores and standalone emulators a platform's own file names."""
    from common import load_platform_config

    try:
        config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
    except (FileNotFoundError, OSError):
        return []
    cores = config.get("cores")
    names = [str(c) for c in cores] if isinstance(cores, list) else []
    return names + [str(c) for c in config.get("standalone_cores") or []]


def _unresolved_findings(platform: str, missing: dict[str, list[str]]) -> list[Finding]:
    """One row per platform: the names its targets list that no profile claims.

    A buildbot name without a profile is a core the target filter cannot
    see, and a platform's own emulator id without one is an emulator nobody has
    profiled yet. Both are actionable, so both are listed, but as one row so
    the backlog does not bury the day's changes.
    """
    if not missing:
        return []
    names = sorted(missing)
    shown = ", ".join(names[:SHOWN_NAMES]) + (
        f", ... (--json lists all {len(names)})" if len(names) > SHOWN_NAMES else ""
    )
    return [
        Finding(
            "targets",
            f"{platform} cores",
            STALE,
            local=f"{len(names)} without a profile",
            detail=f"cores: alias or _overrides remove_cores needed for {shown}",
            items=names,
        )
    ]


def _age_days(stamp: str, now: datetime) -> int | None:
    try:
        then = datetime.strptime(stamp[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (now - then).days


# --- rom folders ------------------------------------------------------------


def romfolder_sources(platforms_dir: Path) -> dict[str, dict]:
    """setup -> its platforms/romfolders/_sources/<setup>.yml."""
    out = {}
    for path in sorted((platforms_dir / "romfolders" / "_sources").glob("*.yml")):
        with path.open(encoding="utf-8") as fh:
            out[path.stem] = yaml_load(fh) or {}
    return out


def _os_source(doc: dict) -> dict:
    """The source the setup is pinned on: `os`, else the first declared.
    The others follow from it (an EmulationStation pinned by a package.mk)."""
    sources = doc.get("sources") or {}
    return sources.get("os") or next(iter(sources.values()), {})


def platform_revision(setup: str, doc: dict, platforms_dir: Path) -> str:
    """The revision the setup's own platform file was scraped at, when the
    setup is a registered platform read from the same repository; '' else."""
    path = platforms_dir / f"{setup}.yml"
    if setup not in load_platform_registry(str(platforms_dir)) or not path.is_file():
        return ""
    with path.open(encoding="utf-8") as fh:
        source = str((yaml_load(fh) or {}).get("source") or "")
    repo = upstream.parse_repo(str(_os_source(doc).get("repo") or ""))
    if repo is None or f"/{repo.slug.lower()}/" not in source.lower() + "/":
        return ""
    return export_native.source_revision(source)


def romfolder_pin_drift(setup: str, doc: dict, platforms_dir: Path) -> str | None:
    """Why the folders and the BIOS of one platform come from two revisions,
    None when they do not or when only the forge can tell (a tag on one
    side, a commit on the other)."""
    revision = platform_revision(setup, doc, platforms_dir)
    os_source = _os_source(doc)
    tag, commit = os_source.get("tag"), str(os_source.get("commit") or "")
    if not revision or revision in (tag, commit):
        return None
    if tag or len(revision) == len(commit):
        return f"platforms/{setup}.yml was scraped at {revision[:12]}, the rom folders at {tag or commit[:12]}"
    return None


def check_romfolders(platforms_dir: Path, cache_dir: str, offline: bool) -> list[Finding]:
    """The pins of platforms/romfolders/_sources/ against what they follow.

    A setup that is a registered platform is read at the revision its
    platform file was scraped at: the games-on-card mode otherwise installs
    the BIOS of one release for the folders of another. Any other setup is
    compared with its project's newest release, or with its branch head
    when the project publishes none. A pin is moved by hand, then
    `python -m scripts.scraper.romfolders --setup NAME` reads it again.
    """
    findings: list[Finding] = []
    for setup, doc in romfolder_sources(platforms_dir).items():
        os_source = _os_source(doc)
        pin = str(os_source.get("tag") or str(os_source.get("commit") or "")[:12])
        drift = romfolder_pin_drift(setup, doc, platforms_dir)
        if drift:
            findings.append(Finding("romfolders", setup, STALE, local=pin, detail=drift))
            continue
        revision = platform_revision(setup, doc, platforms_dir)
        repo = upstream.parse_repo(str(os_source.get("repo") or ""))
        commit = str(os_source.get("commit") or "")
        if revision and revision in (os_source.get("tag"), commit):
            findings.append(Finding("romfolders", setup, OK, local=pin,
                                    detail=f"read where platforms/{setup}.yml is"))
            continue
        if offline:
            findings.append(Finding("romfolders", setup, SKIPPED, local=pin, detail="offline"))
            continue
        if repo is None or not commit:
            findings.append(Finding("romfolders", setup, UNKNOWN, local=pin, detail="no forge to ask"))
            continue
        findings.append(_romfolder_upstream(setup, repo, os_source, revision, cache_dir))
    return findings


def _romfolder_upstream(
    setup: str, repo: upstream.Repo, os_source: dict, revision: str, cache_dir: str,
) -> Finding:
    commit, tag = str(os_source["commit"]), os_source.get("tag")
    pin = str(tag or commit[:12])
    if revision:
        # The platform names a tag and the setup a commit: the tag's commit decides.
        tagged = upstream.resolve_tag_commit(repo, revision, cache_dir)
        if tagged is None:
            return Finding("romfolders", setup, UNKNOWN, local=pin, detail=f"tag {revision} not listed")
        if tagged == commit:
            return Finding("romfolders", setup, OK, local=pin, detail=f"commit of {revision}")
        return Finding("romfolders", setup, STALE, local=pin, remote=revision,
                       detail=f"platforms/{setup}.yml was scraped at {revision} ({tagged[:12]})")
    pinned_at = (upstream.commit_date(repo, commit, cache_dir) or "")[:10]
    release = upstream.latest_release(repo, cache_dir)
    if release is not None and release.date:
        newer = release.tag != tag and release.date > pinned_at
        return Finding("romfolders", setup, STALE if newer else OK, local=f"{pin} ({pinned_at})",
                       remote=f"{release.tag} ({release.date})",
                       detail="a release is newer than the pin" if newer else "newest release")
    head = upstream.resolve_head(repo, cache_dir)
    if head is None:
        return Finding("romfolders", setup, UNKNOWN, local=pin, detail="branch head unavailable")
    if head == commit:
        return Finding("romfolders", setup, OK, local=pin, detail="branch head")
    counts = upstream.ancestry(repo, commit, head, cache_dir)
    behind = f"{counts[0]} commits behind the branch head" if counts else "the branch head moved"
    return Finding("romfolders", setup, STALE, local=pin, remote=head[:12], detail=behind)


# --- core-info --------------------------------------------------------------


def core_info_blobs(cache_dir: str, offline: bool) -> dict[str, str] | None:
    """Every core the libretro core-info repository describes, with the git
    blob of its .info."""
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
    blobs = {}
    for entry in payload:
        name = entry.get("name", "") if isinstance(entry, dict) else ""
        if name.endswith("_libretro.info"):
            blobs[name[: -len("_libretro.info")]] = str(entry.get("sha") or "")
    return dict(sorted(blobs.items()))


def core_info_names(cache_dir: str, offline: bool) -> list[str] | None:
    """Every core the libretro core-info repository describes."""
    blobs = core_info_blobs(cache_dir, offline)
    return None if blobs is None else list(blobs)


def load_core_info_record(path: Path = CORE_INFO_RECORD) -> dict[str, str] | None:
    if not path.is_file():
        return None
    return dict((json.loads(path.read_text(encoding="utf-8")) or {}).get("blobs") or {})


def record_core_info(
    blobs: dict[str, str], names: list[str], path: Path = CORE_INFO_RECORD
) -> list[str]:
    """Record the current blob of *names* (every .info when empty) as reviewed.

    Naming the cores keeps a change nobody read out of the record.
    """
    unknown = sorted(set(names) - set(blobs))
    if unknown:
        raise InputMissing(
            f"no such .info in core-info: {', '.join(unknown)}. "
            + suggest_names(unknown, list(blobs), "libretro-core-info")
        )
    recorded = load_core_info_record(path) or {}
    recorded.update({n: blobs[n] for n in (names or blobs)})
    payload = {"repository": CORE_INFO_REPO, "blobs": dict(sorted(recorded.items()))}
    write_text_atomic(str(path), json.dumps(payload, indent=2) + "\n")
    return sorted(names or blobs)


def coreinfo_drift(
    blobs: dict[str, str], recorded: dict[str, str], profiles: dict[str, dict]
) -> list[str]:
    """Profiled cores whose .info is not the one recorded as reviewed.

    The .info is no authority, but a new firmwareN_path in it is the
    cheapest sign that a profile needs reading again.
    """
    index = {key.casefold() for key in profile_name_index(profiles)}
    return [n for n, sha in blobs.items()
            if n.casefold() in index and recorded.get(n) != sha]


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


def check_coreinfo(
    profiles: dict[str, dict], cache_dir: str, offline: bool,
    record_path: Path = CORE_INFO_RECORD,
) -> list[Finding]:
    blobs = core_info_blobs(cache_dir, offline)
    if blobs is None and offline:
        # Offline with no cached listing, nothing was asked of the upstream.
        return [Finding("coreinfo", "libretro-core-info", SKIPPED, detail="offline")]
    if blobs is None:
        return [Finding("coreinfo", "libretro-core-info", UNKNOWN, detail="listing unavailable")]
    names = list(blobs)
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
    recorded = load_core_info_record(record_path)
    if recorded is None:
        findings.append(Finding(
            "coreinfo", "reviewed .info", UNKNOWN,
            detail=f"no {record_path.name}: run python scripts/check_freshness.py --record-coreinfo",
        ))
        return findings
    findings.extend(
        Finding(
            "coreinfo", name, STALE,
            local=(recorded.get(name) or "not recorded")[:12], remote=blobs[name][:12],
            detail=(".info changed since reviewed: read its firmware, then "
                    f"python scripts/check_freshness.py --record-coreinfo {name}"),
        )
        for name in coreinfo_drift(blobs, recorded, profiles)
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
    findings.append(_check_buildbot_system())
    return findings


def _check_buildbot_system() -> Finding:
    """The buildbot's system directory against what _data_dirs.yml tracks.

    The registry entries are refreshed above. An asset published since, or
    one the buildbot no longer serves, is only seen by reading its .index.
    """
    import check_buildbot_system  # noqa: PLC0415

    with contextlib.redirect_stdout(io.StringIO()):
        report = check_buildbot_system.check(
            str(REPO_ROOT / "platforms" / "_data_dirs.yml")
        )
    if report.get("error"):
        return Finding("data", "buildbot system", UNKNOWN, detail="index unreachable")
    todo = check_buildbot_system.pending(report)
    if not todo:
        return Finding("data", "buildbot system", OK)
    every = [f"{e['status'].lower()} {e['zip']}" for e in todo]
    names = ", ".join(every[:SHOWN_NAMES])
    more = f", ... (--json lists all {len(todo)})" if len(todo) > SHOWN_NAMES else ""
    return Finding("data", "buildbot system", STALE, local=f"{len(todo)} to track",
                   detail=f"{names}{more} (_data_dirs.yml)", items=every)


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
    findings.append(_check_nointro_games(cache_dir, offline))
    findings.append(_check_redump_games(offline))
    return findings


def _game_catalogs(source: str) -> list[dict]:
    """The committed game catalogs of one source, games/catalogs/<source>/."""
    return [_snapshot(path) for path in sorted((REPO_ROOT / "games" / "catalogs" / source).glob("*.json"))]


def _no_intro_asset_date(cache_dir: str, offline: bool) -> str:
    """The day the mirror last rebuilt its No-Intro pack, empty if unlisted."""
    repo = upstream.parse_repo(NO_INTRO_MIRROR)
    payload = upstream._api(  # noqa: SLF001
        f"{repo.api_base}/repos/{repo.slug}/releases/tags/{NO_INTRO_RELEASE}",
        cache_dir,
        offline,
        upstream.MOVING_TTL,
    )
    for asset in (payload.get("assets") if isinstance(payload, dict) else None) or []:
        if isinstance(asset, dict) and asset.get("name") == NO_INTRO_ASSET:
            return str(asset.get("updated_at", ""))[:10]
    return ""


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _no_intro_row(subject: str, local: str, updated: str) -> Finding:
    """Our import against the mirror's pack, and the pack against today."""
    age = (datetime.fromisoformat(_today()) - datetime.fromisoformat(updated)).days
    if age > NO_INTRO_MAX_AGE_DAYS:
        return Finding(
            "catalogs", subject, STALE, local=local, remote=updated,
            detail=f"the mirror last rebuilt {NO_INTRO_ASSET} on {updated}, {age} days ago, "
                   f"though it rebuilds daily: {NO_INTRO_MIRROR}/actions",
        )
    return Finding(
        "catalogs", subject, STALE if updated > local else OK,
        local=local, remote=updated, detail=f"{NO_INTRO_ASSET} rebuilt {updated}",
    )


def _check_nointro_games(cache_dir: str, offline: bool) -> Finding:
    """games/catalogs/no-intro/ against the pack it was read from. The pack
    holds every DAT: rebuilt after the catalogs were read, it may carry
    games the games-on-card mode does not recognise."""
    subject = "no-intro games"
    fetched = min((str(doc.get("fetched", "")) for doc in _game_catalogs("no-intro")), default="")
    if offline:
        return Finding("catalogs", subject, SKIPPED, local=fetched, detail="offline")
    updated = _no_intro_asset_date(cache_dir, offline)
    if not updated:
        return Finding("catalogs", subject, UNKNOWN, local=fetched, detail="asset not listed")
    return _no_intro_row(subject, fetched, updated)


def redump_datfile_version(code: str) -> str:
    """The version redump.info serves for one datfile, read from the name it
    gives the download: a HEAD request, nothing downloaded."""
    url = game_dat_importer.REDUMP_DATFILE_URL.format(code=code)
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "retrobios/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        disposition = response.headers.get("Content-Disposition", "")
    named = game_dat_importer._DISPOSITION.search(disposition)  # noqa: SLF001
    match = game_dat_importer._REDUMP_FILE.match(named["file"]) if named else None  # noqa: SLF001
    if not match:
        raise ValueError(f"{url} names no datfile")
    return f"{match['date']} {match['time']}"


def _check_redump_games(offline: bool) -> Finding:
    """games/catalogs/redump/ against the datfiles redump.info serves now.
    A disc dumped since is not recognised by the games-on-card mode."""
    subject = "redump games"
    local = {doc.get("system"): str(doc.get("version", "")) for doc in _game_catalogs("redump")}
    newest = max(local.values(), default="")
    if offline:
        return Finding("catalogs", subject, SKIPPED, local=newest, detail="offline")
    changed = []
    remote_newest = ""
    for code, (_name, system, _floor) in sorted(game_dat_importer.REDUMP_DATS.items()):
        try:
            remote = redump_datfile_version(code)
        except (OSError, ValueError) as exc:
            return Finding("catalogs", subject, UNKNOWN, local=newest, detail=str(exc))
        remote_newest = max(remote_newest, remote)
        if local.get(system) != remote:
            changed.append(system)
    return Finding(
        "catalogs", subject, STALE if changed else OK, local=newest, remote=remote_newest,
        detail=(f"changed: {', '.join(changed)}" if changed else f"{len(local)} DATs"),
        items=changed,
    )


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
    updated = _no_intro_asset_date(cache_dir, offline)
    if not updated:
        return Finding("catalogs", "no-intro", UNKNOWN, local=imported, detail="asset not listed")
    return _no_intro_row("no-intro", imported, updated)


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


def parse_npm_pins(text: str) -> dict[str, str]:
    """Package -> the version a package.json names, dependencies of both kinds."""
    data = json.loads(text)
    pins: dict[str, str] = {}
    for key in ("dependencies", "devDependencies"):
        pins.update({str(k): str(v) for k, v in (data.get(key) or {}).items()})
    return pins


def npm_latest(name: str) -> str | None:
    payload = upstream._http_json(NPM_URL.format(name=name))  # noqa: SLF001
    if not isinstance(payload, dict):
        return None
    return str(payload.get("version") or "") or None


def _npm_findings() -> list[Finding]:
    """One row per site dependency: an exact pin is stale once npm's latest
    release is newer, since nothing else asks npm."""
    findings = []
    for name, pinned in sorted(parse_npm_pins(SITE_PACKAGE.read_text(encoding="utf-8")).items()):
        subject = f"npm:{name}"
        if not re.fullmatch(r"\d+(\.\d+)*", pinned):
            findings.append(Finding("ci", subject, UNKNOWN, local=pinned, detail="a range, not an exact pin"))
            continue
        try:
            latest = npm_latest(name)
        except upstream.UpstreamError as exc:
            findings.append(Finding("ci", subject, UNKNOWN, local=pinned, detail=str(exc)))
            continue
        if latest is None:
            findings.append(Finding("ci", subject, UNKNOWN, local=pinned, detail="not on npm"))
            continue
        newer = _version_tuple(latest) > _version_tuple(pinned)
        findings.append(
            Finding(
                "ci",
                subject,
                STALE if newer else OK,
                local=pinned,
                remote=latest,
                detail="a newer release is out" if newer else "",
            )
        )
    return findings


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
        findings.append(Finding("ci", "workflow and site pins", SKIPPED, detail="offline"))
        return findings
    findings.extend(_npm_findings())
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
    """The bootstraps pin install.py by SHA-256, so a stale pin refuses every install."""
    stale = pin_installer.stale_pins(REPO_ROOT)
    return Finding(
        "ci",
        "install.py pin",
        STALE if stale else OK,
        local=pin_installer.installer_sha256(REPO_ROOT)[:12],
        detail=(
            f"pin outdated in {', '.join(stale)}, {pin_installer.COMMAND} writes it"
            if stale else "install.sh and install.ps1 match"
        ),
    )


# --- profiles ---------------------------------------------------------------


def check_source_paths(profiles: dict) -> Finding:
    """The site links a cited path only where source-paths.json records it
    in the tree the profile pins. A recorded tree no profile pins any more,
    or a pinned tree the record lacks, means a pin moved or a profile was
    added and `sitesources.py --fetch` was not run after it. Every tree a run
    tries is recorded, read or not, so a lacking one was never tried."""
    import sitesources  # noqa: PLC0415

    pinned = {
        sitesources.tree_key(repo, pin)
        for profile in profiles.values() if sitesources.cited_paths(profile)
        for repo, pin in sitesources.profile_trees(profile)
    } | {
        # The platform build files pin_build names, linked from a page too.
        sitesources.tree_key(repo, pin)
        for profile in profiles.values()
        for repo, pin, _path in sitesources.build_files(profile)
    }
    try:
        recorded = set(json.loads(sitesources.SOURCE_PATHS.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        return Finding("profiles", "source-paths.json", ERROR, detail=str(exc))
    orphaned = sorted(recorded - pinned)
    unrecorded = sorted(pinned - recorded)
    problems = [f"{len(found)} {words}" for found, words in (
        (orphaned, "recorded trees no profile pins"),
        (unrecorded, "pinned trees not recorded"),
    ) if found]
    return Finding(
        "profiles",
        "source-paths.json",
        STALE if problems else OK,
        local=f"{len(recorded)} trees",
        detail=(", ".join(problems) + ": run python scripts/sitesources.py --fetch") if problems
        else "every pinned tree is recorded, and only those",
    )


def build_variable(lines: list[str], variable: str) -> str | None:
    """The value the first assignment to ``variable`` gives in a build file.

    Read as a Buildroot .mk (`X_VERSION = sha`), a LibreELEC package.mk
    (`PKG_VERSION="sha"`) or a RetroPie scriptmodule (`rp_module_repo="git
    URL tag"`, `local version="20250829"`): quotes and a trailing comment go,
    the rest is compared as written.
    """
    assignment = re.compile(
        rf"^\s*(?:local\s+|export\s+)?{re.escape(variable)}\s*[:?+]?=\s*(.*)$"
    )
    for line in lines:
        match = assignment.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if value[:1] in "\"'":
            end = value.find(value[0], 1)
            return value[1:end] if end > 0 else value[1:]
        return value.split(" #", 1)[0].strip()
    return None


def pin_build_revision(reference: dict, platforms_dir: Path) -> str:
    """The revision of the platform repository its YAML was last scraped at,
    '' when the platform is not registered or reads another repository."""
    path = platforms_dir / f"{reference.get('platform', '')}.yml"
    repo = upstream.parse_repo(str(reference.get("repo") or ""))
    if repo is None or not path.is_file():
        return ""
    with path.open(encoding="utf-8") as fh:
        source = str((yaml_load(fh) or {}).get("source") or "")
    if f"/{repo.slug.lower()}/" not in source.lower() + "/":
        return ""
    return export_native.source_revision(source)


def check_pin_builds(
    profiles: dict, platforms_dir: Path, cache_dir: str, offline: bool,
) -> list[Finding]:
    """Each `pin_build:` read again where the platform now stands.

    A pin_frozen pin is held because one platform builds that revision, and
    nothing read the build file again: Recalbox moving mame0278 to another
    commit left the profile describing a build no platform ships. The file
    is read at the revision the platform's own YAML was scraped at, or at
    the repository's branch head for a platform this repository does not
    scrape, and its variable compared with the value the profile recorded.
    """
    findings: list[Finding] = []
    unreferenced = sorted(
        name for name, profile in profiles.items()
        if profile.get("pin_frozen") and not profile.get("pin_build")
    )
    if unreferenced:
        findings.append(Finding(
            "profiles", "pin_frozen without pin_build", SKIPPED,
            local=f"{len(unreferenced)} profiles",
            detail="no platform build file names their revision: "
                   + ", ".join(unreferenced[:SHOWN_NAMES])
                   + (", ..." if len(unreferenced) > SHOWN_NAMES else ""),
            items=unreferenced,
        ))
    for name, profile in sorted(profiles.items()):
        for reference in profile.get("pin_build") or []:
            subject = f"{name} ({reference['platform']})"
            recorded = str(reference["value"])
            revision = pin_build_revision(reference, platforms_dir)
            if revision == str(reference["revision"]):
                findings.append(Finding(
                    "profiles", subject, OK, local=recorded[:12],
                    detail=f"read where platforms/{reference['platform']}.yml is",
                ))
                continue
            repo = upstream.parse_repo(str(reference["repo"]))
            try:
                at = revision or upstream.resolve_head(repo, cache_dir, offline)
                lines = upstream.fetch_file(repo, at, reference["path"], cache_dir, offline) \
                    if at else None
                if at and lines is None:
                    # A file of a submodule is read at the commit the
                    # platform's tree pins: KNULLI builds Batocera's
                    # amiberry package through its batocera submodule.
                    modules = upstream.fetch_file(repo, at, ".gitmodules", cache_dir, offline)
                    declared = upstream.submodule_urls("\n".join(modules or ()), repo)
                    if any(reference["path"].startswith(f"{p}/") for p in declared):
                        linked = upstream.through_gitlink(repo, at, reference["path"],
                                                          cache_dir, offline)
                        if linked is not None:
                            lines = upstream.fetch_file(*linked, cache_dir, offline)
            except upstream.NotCachedError:
                findings.append(Finding("profiles", subject, SKIPPED, local=recorded[:12],
                                        detail="offline, the build file is not cached"))
                continue
            except upstream.UpstreamError as exc:
                findings.append(Finding("profiles", subject, UNKNOWN, local=recorded[:12],
                                        detail=str(exc)))
                continue
            if not at:
                findings.append(Finding("profiles", subject, UNKNOWN, local=recorded[:12],
                                        detail=f"{repo.slug} answered no branch head"))
                continue
            current = None if lines is None else build_variable(lines, reference["variable"])
            if current == recorded:
                findings.append(Finding(
                    "profiles", subject, OK, local=recorded[:12], remote=at[:12],
                    detail=f"{reference['path']} still builds it",
                ))
                continue
            findings.append(Finding(
                "profiles", subject, STALE, local=recorded[:12],
                remote=(current or "gone")[:12],
                detail=(
                    f"{reference['path']} is gone at {at[:12]}" if lines is None
                    else f"{reference['variable']} is no longer set there" if current is None
                    else f"{reference['platform']} now builds {current} "
                         f"({reference['path']} at {at[:12]}): the pin follows the build"
                ),
            ))
    return findings


def check_profiles(run: bool, offline: bool) -> list[Finding]:
    if not run:
        return [
            Finding(
                "profiles",
                "profile_sync",
                SKIPPED,
                detail="pass --profiles, or run python scripts/profile_sync.py --all --triage",
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

    The JSON carries the ref verdicts and the pin against the tip. A profile
    whose refs need review is stale, one the forge could not serve is unknown,
    and one whose upstream moved while every ref still anchors is reported as
    such without being counted as stale. A cited file that gained a file name
    since the pin, or a hash the profile does not declare, is stale too: the
    upstream may load a file the profile does not document.
    """
    if not isinstance(report, list):
        return [Finding("profiles", "profile_sync", ERROR, detail="report is not a list")]
    findings = []
    clean = moved = 0
    for row in report:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "?")
        if row.get("skipped") and row.get("page_version"):
            # Off any forge, the release page is the feed: a version there
            # beyond the declared one is a release the profile does not cover.
            declared, announced = str(row.get("declared_version") or ""), str(row["page_version"])
            if announced == declared:
                status, detail = OK, ""
            elif announced == str(row.get("no_genuine_copy") or ""):
                # Searched for and found only rebuilt: the profile covers the
                # newest build that can be read, until the page moves on.
                status, detail = OK, "no genuine copy of the announced release"
            else:
                status, detail = STALE, "a newer release is announced"
            findings.append(Finding("profiles", name, status, local=declared,
                                    remote=announced, detail=detail))
            continue
        if row.get("skipped"):
            # A skip profile_sync counts as a defect (no repository answers,
            # no resolvable pin) is unknown. One that is the profile's nature
            # (an upstream declared gone, a host no forge API serves, no
            # source_ref) is never checkable and does not hold the exit code.
            from profile_sync import ProfileReport

            reason = str(row["skipped"])
            status = UNKNOWN if reason.startswith(ProfileReport.UNCHECKABLE) else SKIPPED
            findings.append(Finding("profiles", name, status, detail=reason))
            continue
        review = row.get("needs_review") or 0
        pin, head = str(row.get("pin") or ""), str(row.get("head") or "")
        added = sorted({
            str(item.get("name"))
            for item in row.get("new_files") or ()
            if isinstance(item, dict) and item.get("since_pin")
        })
        hashes = len(row.get("new_hashes") or ())
        reasons = [f"{review} refs to review"] if review else []
        if added:
            reasons.append(f"new file names since the pin: {', '.join(added)}")
        if hashes:
            reasons.append(f"{hashes} undeclared hashes added since the pin")
        if reasons:
            findings.append(
                Finding(
                    "profiles",
                    name,
                    STALE,
                    local=pin[:8],
                    remote=head[:8],
                    detail=", ".join(reasons),
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
        # Columns are padded, never cut: the profile_sync row says in its
        # local and remote values what to re-read, and lost the end of it.
        local_width = min(max((len(f.local) for f in rows), default=0), 44)
        remote_width = min(max((len(f.remote) for f in rows), default=0), 44)
        # The arrow and the remote value, or as many blanks where a row has none.
        remote_span = 4 + remote_width if remote_width else 0
        for f in rows:
            cols = f"  {f.status:7} {f.subject:{width}}"
            if f.remote:
                cols += f"  {f.local:{local_width}} -> {f.remote:{remote_width}}"
            elif f.local or (f.detail and (local_width or remote_span)):
                # An arrow pointing at nothing read as a lost value. Empty
                # local and remote values still take their columns, or the
                # detail starts where the other rows show theirs.
                cols += f"  {f.local:{local_width}}" + " " * remote_span
            if f.detail:
                cols += f"  {f.detail}"
            lines.append(cols.rstrip())
    counts = {status: sum(1 for f in findings if f.status == status) for status in STATUSES}
    summary = ", ".join(f"{n} {status.lower()}" for status, n in counts.items() if n)
    lines.append(f"\nFRESHNESS: {summary}")
    if counts[STALE]:
        lines.append(
            "refresh_stale.py runs the refresher behind every stale row "
            "(--dry-run lists them first)"
        )
    if counts[UNKNOWN]:
        lines.append("an unknown row is an upstream that could not be read: not up to date")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    # Joined with ", " so argparse wraps between names: one comma-joined
    # token was cut inside "coreinfo".
    parser.add_argument(
        "--only", metavar="AREAS",
        help="comma-separated areas, among: " + ", ".join(AREAS),
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--profiles", action="store_true",
        help="also run profile_sync (slow)",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="no network, local ages only",
    )
    parser.add_argument("--jobs", type=int, default=4, help="parallel scrapers")
    parser.add_argument(
        "--cache-dir", default=upstream.CACHE_DIR,
        help="download cache directory (default: %(default)s)",
    )
    parser.add_argument(
        "--native-cache-dir", default=export_native.DEFAULT_CACHE,
        help="where the platforms' own files are cached (default: %(default)s)",
    )
    parser.add_argument(
        "--truth-dir", default="dist/truth",
        help="directory of the truth models generate_truth writes (default: "
             "%(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--record-coreinfo", nargs="*", metavar="CORE",
        help="record the current .info of CORE (every core when none is named) "
             f"as reviewed in {CORE_INFO_RECORD.relative_to(REPO_ROOT)}, then exit",
    )
    args = parser.parse_args()

    if args.record_coreinfo is not None:
        blobs = core_info_blobs(args.cache_dir, args.offline)
        if not blobs:
            raise InputMissing(
                f"core-info listing not in {args.cache_dir}: run without --offline"
                if args.offline else "core-info listing unavailable: the GitHub API did not answer"
            )
        done = record_core_info(blobs, args.record_coreinfo)
        print(f"recorded {len(done)} .info file(s) as reviewed")
        return 0

    areas = tuple(a.strip() for a in args.only.split(",")) if args.only else AREAS
    unknown = sorted(set(areas) - set(AREAS))
    if unknown:
        parser.error(unknown_areas_message(unknown))

    require_directory(args.platforms_dir, "--platforms-dir")
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
            findings.append(check_emulatorjs(platforms_dir, args.offline))
        if "native" in areas:
            findings.extend(
                check_native(platforms_dir, Path(args.native_cache_dir), Path(args.truth_dir))
            )
        if "targets" in areas:
            findings.extend(check_targets(platforms_dir, workdir, profiles, args.jobs, args.offline))
    if "romfolders" in areas:
        findings.extend(check_romfolders(platforms_dir, args.cache_dir, args.offline))
    if "coreinfo" in areas:
        findings.extend(check_coreinfo(profiles, args.cache_dir, args.offline))
    if "data" in areas:
        findings.extend(check_data(args.offline))
    if "catalogs" in areas:
        findings.extend(check_catalogs(args.cache_dir, args.offline))
    if "ci" in areas:
        findings.extend(check_ci(args.cache_dir, args.offline))
    if "profiles" in areas:
        findings.append(check_source_paths(profiles))
        findings.extend(check_pin_builds(profiles, platforms_dir, args.cache_dir, args.offline))
        findings.extend(check_profiles(args.profiles, args.offline))

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render(findings))
    return exit_code(findings)


def exit_code(findings: list[Finding]) -> int:
    """Zero only when every upstream asked answered and nothing is stale.

    An unknown row is an upstream that could not be read: a run without
    network gave 28 of them and exited 0, the answer of a fresh collection.
    """
    return 1 if any(f.status in (STALE, ERROR, UNKNOWN) for f in findings) else 0


def unknown_areas_message(unknown: list[str]) -> str:
    """The refusal of --only, naming the areas it accepts."""
    import difflib

    hints = [
        f"{name} (did you mean {close[0]}?)" if close else name
        for name in unknown
        for close in [difflib.get_close_matches(name, AREAS, n=1)]
    ]
    return f"unknown area: {', '.join(hints)}. Areas: {', '.join(AREAS)}"


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
