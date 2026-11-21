"""Platform files rescraped and diffed, and the EmulatorJS release RomM installs."""

from __future__ import annotations

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core import upstream
from model.registry import list_registered_platforms, load_platform_registry
from model.sources import source_yaml_file
from freshness.findings import ERROR, OK, SKIPPED, STALE, UNKNOWN, Finding
from freshness.platformdiff import diff_platform
from freshness.rescrape import scrape_into_copy
from freshness.scrapers import platform_scraper


def _scrapable_platforms(platforms_dir: Path) -> list[tuple[str, str, Path]]:
    """(platform, scraper module, file) for every registered platform.

    A platform that only inherits another and declares no source of its own
    (Lakka) has nothing to scrape: its scraper writes the parent's file.
    """
    registry = load_platform_registry(platforms_dir, required=True)
    rows = []
    for name in list_registered_platforms(str(platforms_dir)):
        path = platforms_dir / f"{name}.yml"
        if not path.is_file():
            continue
        config = source_yaml_file(path) or {}
        module = platform_scraper(registry.get(name) or {})
        if not module or (config.get("inherits") and not config.get("source")):
            continue
        rows.append((name, module, path))
    return rows


def check_platforms(platforms_dir: Path, workdir: Path, jobs: int) -> list[Finding]:
    rows = _scrapable_platforms(platforms_dir)
    registry = load_platform_registry(platforms_dir, required=True)
    findings: list[Finding] = []

    def run(row: tuple[str, str, Path]) -> Finding:
        name, _module, path = row
        try:
            fresh, error = scrape_into_copy("platforms", name, path, workdir, registry)
        except subprocess.TimeoutExpired:
            return Finding("platforms", name, ERROR, detail="scraper timed out")
        if error:
            return Finding("platforms", name, ERROR, detail=error)
        old = source_yaml_file(path) or {}
        new = source_yaml_file(fresh) or {}
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
    local = str((source_yaml_file(platforms_dir / "emulatorjs.yml") or {}).get("version", ""))
    if offline:
        return Finding("platforms", subject, SKIPPED, local=local, detail="offline")
    tag = str((source_yaml_file(platforms_dir / "romm.yml") or {}).get("version", ""))
    for path in ROMM_DOCKERFILES:
        try:
            text = upstream.http_text(
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
