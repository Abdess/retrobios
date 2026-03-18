#!/usr/bin/env python3
"""Refresh cached data directories from upstream repositories.

Reads platforms/_data_dirs.yml, compares cached commit SHAs against
remote, and re-downloads stale entries.

Usage:
    python scripts/refresh_data_dirs.py --dry-run
    python scripts/refresh_data_dirs.py --key dolphin-sys
    python scripts/refresh_data_dirs.py --force
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

log = logging.getLogger(__name__)

DEFAULT_REGISTRY = "platforms/_data_dirs.yml"
VERSIONS_FILE = "data/.versions.json"
USER_AGENT = "retrobios/1.0"
REQUEST_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 300


def load_registry(registry_path: str = DEFAULT_REGISTRY) -> dict[str, dict]:
    if yaml is None:
        raise ImportError("PyYAML required: pip install pyyaml")
    path = Path(registry_path)
    if not path.exists():
        raise FileNotFoundError(f"Registry not found: {registry_path}")
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return data.get("data_directories", {})


def _load_versions(versions_path: str = VERSIONS_FILE) -> dict[str, dict]:
    path = Path(versions_path)
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def _save_versions(versions: dict[str, dict], versions_path: str = VERSIONS_FILE) -> None:
    path = Path(versions_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(versions, f, indent=2, sort_keys=True)
        f.write("\n")


def _api_request(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and "github" in url:
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read())


def _parse_repo_from_url(source_url: str) -> tuple[str, str, str]:
    """Extract (host_type, owner, repo) from a tarball URL.

    Returns host_type as 'github' or 'gitlab'.
    """
    if "github.com" in source_url:
        # https://github.com/owner/repo/archive/{version}.tar.gz
        parts = source_url.split("github.com/")[1].split("/")
        return "github", parts[0], parts[1]
    if "gitlab.com" in source_url:
        parts = source_url.split("gitlab.com/")[1].split("/")
        return "gitlab", parts[0], parts[1]
    raise ValueError(f"Unsupported host in URL: {source_url}")


def get_remote_sha(source_url: str, version: str) -> str | None:
    """Fetch the current commit SHA for a branch/tag from GitHub or GitLab."""
    try:
        host_type, owner, repo = _parse_repo_from_url(source_url)
    except ValueError:
        log.warning("cannot parse repo from URL: %s", source_url)
        return None

    try:
        if host_type == "github":
            url = f"https://api.github.com/repos/{owner}/{repo}/commits/{version}"
            data = _api_request(url)
            return data["sha"]
        else:
            encoded = f"{owner}%2F{repo}"
            url = f"https://gitlab.com/api/v4/projects/{encoded}/repository/branches/{version}"
            data = _api_request(url)
            return data["commit"]["id"]
    except (urllib.error.URLError, KeyError, OSError) as exc:
        log.warning("failed to fetch remote SHA for %s/%s@%s: %s", owner, repo, version, exc)
        return None


def _is_safe_tar_member(member: tarfile.TarInfo, dest: Path) -> bool:
    """Reject path traversal and absolute paths in tar members."""
    if member.name.startswith("/") or ".." in member.name.split("/"):
        return False
    resolved = (dest / member.name).resolve()
    if not str(resolved).startswith(str(dest.resolve())):
        return False
    return True


def _download_and_extract(
    source_url: str,
    source_path: str,
    local_cache: str,
    exclude: list[str] | None = None,
) -> int:
    """Download tarball, extract source_path subtree to local_cache.

    Returns the number of files extracted.
    """
    exclude = exclude or []
    cache_dir = Path(local_cache)

    with tempfile.TemporaryDirectory() as tmpdir:
        tarball_path = Path(tmpdir) / "archive.tar.gz"
        log.info("downloading %s", source_url)

        req = urllib.request.Request(source_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            with open(tarball_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)

        log.info("extracting %s -> %s", source_path, local_cache)

        prefix = source_path.rstrip("/") + "/"
        file_count = 0

        with tarfile.open(tarball_path, "r:gz") as tf:
            extract_dir = Path(tmpdir) / "extract"
            extract_dir.mkdir()

            for member in tf.getmembers():
                if not member.name.startswith(prefix) and member.name != source_path:
                    continue

                rel = member.name[len(prefix):]
                if not rel:
                    continue

                # skip excluded subdirectories
                top_component = rel.split("/")[0]
                if top_component in exclude:
                    continue

                if not _is_safe_tar_member(member, extract_dir):
                    log.warning("skipping unsafe tar member: %s", member.name)
                    continue

                # rewrite member name to relative path
                member_copy = tarfile.TarInfo(name=rel)
                member_copy.size = member.size
                member_copy.mode = member.mode
                member_copy.type = member.type

                if member.isdir():
                    (extract_dir / rel).mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    dest_file = extract_dir / rel
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    with tf.extractfile(member) as src:
                        if src is None:
                            continue
                        with open(dest_file, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                    file_count += 1

        # atomic swap: remove old cache, move new into place
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(extract_dir), str(cache_dir))

    return file_count


def refresh_entry(
    key: str,
    entry: dict,
    *,
    force: bool = False,
    dry_run: bool = False,
    versions_path: str = VERSIONS_FILE,
) -> bool:
    """Refresh a single data directory entry.

    Returns True if the entry was refreshed (or would be in dry-run mode).
    """
    version = entry.get("version", "master")
    source_url = entry["source_url"].format(version=version)
    source_path = entry["source_path"].format(version=version)
    local_cache = entry["local_cache"]
    exclude = entry.get("exclude", [])

    versions = _load_versions(versions_path)
    cached = versions.get(key, {})
    cached_sha = cached.get("sha")

    needs_refresh = force or not Path(local_cache).exists()

    if not needs_refresh:
        remote_sha = get_remote_sha(entry["source_url"], version)
        if remote_sha is None:
            log.warning("[%s] could not check remote, skipping", key)
            return False
        needs_refresh = remote_sha != cached_sha
    else:
        remote_sha = get_remote_sha(entry["source_url"], version) if not force else None

    if not needs_refresh:
        log.info("[%s] up to date (sha: %s)", key, cached_sha[:12] if cached_sha else "?")
        return False

    if dry_run:
        log.info("[%s] would refresh (version: %s, cached sha: %s)", key, version, cached_sha or "none")
        return True

    try:
        file_count = _download_and_extract(source_url, source_path, local_cache, exclude)
    except (urllib.error.URLError, OSError, tarfile.TarError) as exc:
        log.warning("[%s] download failed: %s", key, exc)
        return False

    # update version tracking
    if remote_sha is None:
        remote_sha = get_remote_sha(entry["source_url"], version)
    versions = _load_versions(versions_path)
    versions[key] = {"sha": remote_sha or "", "version": version}
    _save_versions(versions, versions_path)

    log.info("[%s] refreshed: %d files extracted to %s", key, file_count, local_cache)
    return True


def refresh_all(
    registry: dict[str, dict],
    *,
    force: bool = False,
    dry_run: bool = False,
    versions_path: str = VERSIONS_FILE,
) -> dict[str, bool]:
    """Refresh all entries in the registry.

    Returns a dict mapping key -> whether it was refreshed.
    """
    results = {}
    for key, entry in registry.items():
        results[key] = refresh_entry(
            key, entry, force=force, dry_run=dry_run, versions_path=versions_path,
        )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh cached data directories from upstream")
    parser.add_argument("--key", help="Refresh only this entry")
    parser.add_argument("--force", action="store_true", help="Re-download even if up to date")
    parser.add_argument("--dry-run", action="store_true", help="Preview without downloading")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY, help="Path to _data_dirs.yml")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    registry = load_registry(args.registry)

    if args.key:
        if args.key not in registry:
            log.error("unknown key: %s (available: %s)", args.key, ", ".join(registry))
            raise SystemExit(1)
        refresh_entry(args.key, registry[args.key], force=args.force, dry_run=args.dry_run)
    else:
        refresh_all(registry, force=args.force, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
