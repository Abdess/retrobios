"""Upstream MAME and FBNeo DATs, downloaded once into a cache read offline."""

from __future__ import annotations

import re
from pathlib import Path

from core.hashing import git_blob_sha
from .base_scraper import (
    BlobMismatchError,
    download,
    fetch_branch_head,
    fetch_verified_blob,
    github_json,
)

MAME_LISTXML_URL = (
    "https://github.com/mamedev/mame/releases/download/{tag}/{tag}lx.zip"
)
FBNEO_REPO = "libretro/FBNeo"
FBNEO_API = f"https://api.github.com/repos/{FBNEO_REPO}"


def api_json(url: str) -> object:
    """An api.github.com answer, ConnectionError when it cannot be read."""
    return github_json(url, f"cannot read {url}", timeout=60, error=ConnectionError)


def is_tracked_dat(item: object) -> bool:
    """Whether an entry of the FBNeo ``dats`` listing is a DAT the import reads."""
    return (
        isinstance(item, dict)
        and item.get("type") == "file"
        and str(item.get("name", "")).lower().endswith(".dat")
    )


def mame_label(pack_stem: str) -> str:
    """The snapshot label of a MAME listxml pack (``mame0289lx`` gives ``MAME mame0289``)."""
    return f"MAME {pack_stem.replace('lx', '')}"


def label_version(label: str) -> str | None:
    """The MAME tag a snapshot label names, None for a label without one."""
    match = re.search(r"\b(mame\d{4})\b", label)
    return match.group(1) if match else None


class NotCached(FileNotFoundError):
    """The cache holds no pack for the revision asked."""


def _listxml_path(tag: str, cache_dir: Path) -> Path:
    return cache_dir / f"{tag}lx.zip"


def _fbneo_folder(commit: str, cache_dir: Path) -> Path:
    # One folder per commit: a folder refilled for whatever revision was
    # last asked gave an offline read the DATs of another pin.
    return cache_dir / "fbneo-dats" / commit


def fetch_pack(
    source: str, tag: str, cache_dir: Path
) -> tuple[Path, dict[str, str]]:
    """Download the upstream DAT for *source*.

    MAME ships its ``-listxml`` output as a release asset, and FBNeo keeps its
    DATs in the repository, so neither needs a browser. The second value
    names the upstream state fetched: empty for a release asset, whose tag
    already says which version it is, and the git blob sha of every DAT for
    FBNeo, whose files change under a constant header version.
    """
    if source == "mame":
        listxml = _listxml_path(tag, cache_dir)
        download(MAME_LISTXML_URL.format(tag=tag), listxml, skip_existing=True)
        return listxml, {}

    # The revision is resolved to a commit first and everything is read at
    # that commit: a branch URL is served through a CDN cache, so the bytes
    # could predate the listing that named their blob.
    sha = fetch_branch_head(FBNEO_REPO, None if tag == "latest" else tag)
    listing = api_json(f"{FBNEO_API}/contents/dats?ref={sha}")
    if not isinstance(listing, list):
        raise BlobMismatchError(f"libretro/FBNeo lists no dats at {sha}")
    target = _fbneo_folder(sha, cache_dir)
    target.mkdir(parents=True, exist_ok=True)
    blobs: dict[str, str] = {}
    for item in listing:
        if not is_tracked_dat(item):
            continue
        fetch_verified_blob(
            item["download_url"], target / item["name"], item["sha"],
            f" of libretro/FBNeo {sha}",
        )
        blobs[item["name"]] = item["sha"]
    # A DAT the revision does not carry is not read from an older fetch.
    for stale in target.glob("*"):
        if stale.is_file() and stale.name not in blobs:
            stale.unlink()
    return target, blobs


def cached_pack(
    source: str, revision: str, cache_dir: Path
) -> tuple[Path, dict[str, str]]:
    """What fetch_pack wrote for *revision* (a MAME tag, a full FBNeo commit),
    read offline. The FBNeo blobs are recomputed from the bytes."""
    if source == "mame":
        listxml = _listxml_path(revision, cache_dir)
        if not listxml.is_file():
            raise NotCached(f"{listxml} is not cached")
        return listxml, {}
    folder = _fbneo_folder(revision, cache_dir)
    blobs = {
        p.name: git_blob_sha(p.read_bytes())
        for p in (sorted(folder.iterdir()) if folder.is_dir() else ())
        if is_tracked_dat({"type": "file" if p.is_file() else "dir", "name": p.name})
    }
    if not blobs:
        raise NotCached(f"{folder} is not cached")
    return folder, blobs
