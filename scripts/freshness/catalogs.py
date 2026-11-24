"""Dump catalogs, game catalogs and romset recipes against what upstream serves."""

from __future__ import annotations

import http.client
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from core import upstream
from core.paths import REPO_ROOT
from scripts.scraper import game_dat_importer
from scripts.scraper.dat_fetch import is_tracked_dat, label_version
from scripts.scraper.redump_dat_scraper import fetch_snapshot
from freshness.findings import (
    FBNEO_RECIPES, MAME_RECIPES, NO_INTRO_GAMES, OK, REDUMP_GAMES, SKIPPED, STALE, UNKNOWN,
    Finding,
)


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
    payload = upstream.cached_api(
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
    subject = NO_INTRO_GAMES
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
    disposition = upstream.open_retrying(
        request, lambda response: response.headers.get("Content-Disposition", ""), timeout=60
    )
    version = game_dat_importer.served_version(game_dat_importer.datfile_name(disposition) or "")
    if not version:
        raise ValueError(f"{url} names no datfile")
    return version


def _check_redump_games(offline: bool) -> Finding:
    """games/catalogs/redump/ against the datfiles redump.info serves now.
    A disc dumped since is not recognised by the games-on-card mode."""
    subject = REDUMP_GAMES
    # The stamp of the file the import read, the one the server names now.
    local = {
        doc.get("system"): game_dat_importer.served_version(str((doc.get("archive") or {}).get("file", "")))
        for doc in _game_catalogs("redump")
    }
    newest = max(local.values(), default="")
    if offline:
        return Finding("catalogs", subject, SKIPPED, local=newest, detail="offline")
    changed = []
    remote_newest = ""
    for code, (_name, system, _floor) in sorted(game_dat_importer.REDUMP_DATS.items()):
        try:
            remote = redump_datfile_version(code)
        except (OSError, http.client.HTTPException, upstream.UpstreamError, ValueError) as exc:
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
        html = upstream.http_text(TOSEC_DOWNLOADS)
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
    tags = {label_version(str(label)) for label in (recipes.get("dats") or {})}
    return sorted(tag for tag in tags if tag)


def _check_mame(cache_dir: str, offline: bool) -> Finding:
    local = _snapshot(REPO_ROOT / "recipes" / "mame.json")
    versions = mame_versions(local)
    newest = versions[-1] if versions else "none"
    if offline:
        return Finding("catalogs", MAME_RECIPES, SKIPPED, local=newest, detail="offline")
    release = upstream.latest_release(upstream.parse_repo(MAME_REPO), cache_dir, offline)
    if release is None:
        return Finding("catalogs", MAME_RECIPES, UNKNOWN, local=newest, detail="no release seen")
    return Finding(
        "catalogs",
        MAME_RECIPES,
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
        if is_tracked_dat(item)
    }
    drifted = sorted(
        name for name in set(recorded) | set(remote) if recorded.get(name) != remote.get(name)
    )
    return drifted, True


def _check_fbneo(cache_dir: str, offline: bool) -> Finding:
    local = _snapshot(REPO_ROOT / "recipes" / "fbneo.json")
    imported = str(local.get("imported_at", ""))
    if offline:
        return Finding("catalogs", FBNEO_RECIPES, SKIPPED, local=imported, detail="offline")
    repo = upstream.parse_repo(FBNEO_REPO)
    listing = upstream.cached_api(
        f"{repo.api_base}/repos/{repo.slug}/contents/dats",
        cache_dir,
        offline,
        upstream.MOVING_TTL,
    )
    if not isinstance(listing, list):
        return Finding("catalogs", FBNEO_RECIPES, UNKNOWN, local=imported, detail="dats/ listing unavailable")
    drifted, tracked = fbneo_blob_drift(local, listing)
    if not tracked:
        return Finding(
            "catalogs",
            FBNEO_RECIPES,
            STALE,
            local=imported,
            detail="snapshot records no upstream blobs: re-import with --fetch",
        )
    shown = ", ".join(n.removeprefix("FinalBurn Neo (ClrMame Pro XML, ").removesuffix(" only).dat") for n in drifted[:4])
    return Finding(
        "catalogs",
        FBNEO_RECIPES,
        STALE if drifted else OK,
        local=imported,
        remote=f"{len(listing)} DATs listed",
        detail=(f"{len(drifted)} DAT(s) changed upstream: {shown}" if drifted else "every DAT blob matches"),
    )
