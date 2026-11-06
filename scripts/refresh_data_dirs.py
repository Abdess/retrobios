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
import contextlib
import json
import logging
import os
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from artifacts import file_lock as _file_lock, set_plain_mode
from common import InputMissing, github_token, platform_arg, require_platform, suggest_names, yaml_load

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
# A mirror sometimes answers with a page that is not the archive: the
# buildbot's ScummVM.zip failed CI once as "File is not a zip file" and
# downloaded fine minutes later. Seconds to wait before each retry.
DOWNLOAD_RETRY_WAITS = (5, 20)
_TRANSIENT = (urllib.error.URLError, OSError, tarfile.TarError, zipfile.BadZipFile, EOFError)


def load_registry(registry_path: str = DEFAULT_REGISTRY) -> dict[str, dict]:
    if yaml is None:
        raise ImportError("PyYAML required: pip install pyyaml")
    path = Path(registry_path)
    if not path.exists():
        raise InputMissing(f"Registry not found: {registry_path}")
    with open(path) as f:
        data = yaml_load(f) or {}
    return data.get("data_directories", {})


def cache_lock(
    cache_dir: str | Path, shared: bool = False
) -> contextlib.AbstractContextManager[None]:
    """The lock a refresh holds while it swaps cache_dir.

    A reader takes it shared: a pack walking data/sdlpal while another run
    swapped the tree shipped part of it, or nothing.
    """
    cache_dir = Path(cache_dir)
    return _announced_lock(cache_dir.with_name(f".{cache_dir.name}.lock"), shared, cache_dir)


def _wait_message(lock_path: Path, shared: bool, cache_dir: Path) -> str:
    """Who to wait for, and, for a refresh, how not to.

    The bare "another run holds it" named neither the lock nor its holder,
    and the build waited with no limit.
    """
    message = (
        f"waiting for {cache_dir}: another run holds {lock_path} "
        f"(lsof {lock_path} names it)"
    )
    if not shared:
        message += (
            ". generate_pack.py --no-refresh-data, or --offline there and in"
            " pipeline.py, builds from the cache as it is without waiting"
        )
    return message


@contextlib.contextmanager
def _announced_lock(lock_path: Path, shared: bool, cache_dir: Path) -> Iterator[None]:
    """file_lock, saying so when it has to wait.

    A pipeline holds every cache for its whole run: a refresh started beside
    it waited hours with nothing on screen.
    """
    try:
        import fcntl
    except ImportError:
        with _file_lock(lock_path, shared=shared):
            yield
        return
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
    with open(lock_path, "a") as handle:
        try:
            fcntl.flock(handle, mode | fcntl.LOCK_NB)
        except BlockingIOError:
            log.warning(_wait_message(lock_path, shared, cache_dir))
            fcntl.flock(handle, mode)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def hold_data_dirs(stack: contextlib.ExitStack, registry: dict) -> None:
    """Hold every cached data directory shared for the life of *stack*.

    A pack resolves names against a tree, then copies the file minutes
    later. A refresh swapping the tree in between shipped bytes nobody
    verified, or died on a file the new tree no longer has. A refresh waits
    for the holders. Never called before a refresh in the same process:
    the exclusive lock would wait on this one. A cache not yet on disk is
    held too: the lock sits beside the tree, and skipped, a refresh could
    install the tree after verify ran and before the packs read it.
    """
    for entry in registry.values():
        cache = entry.get("local_cache", "")
        if cache:
            stack.enter_context(cache_lock(cache, shared=True))


def _load_versions(versions_path: str = VERSIONS_FILE) -> dict[str, dict]:
    path = Path(versions_path)
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def _save_versions(
    versions: dict[str, dict], versions_path: str = VERSIONS_FILE
) -> None:
    """Write the version file whole or not at all.

    Truncating in place let a concurrent reader load an empty file and die
    on JSONDecodeError. The scratch file sits beside the target so the
    rename stays on one filesystem.
    """
    path = Path(versions_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, scratch = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w") as f:
            json.dump(versions, f, indent=2, sort_keys=True)
            f.write("\n")
        set_plain_mode(scratch)
        os.replace(scratch, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(scratch)
        raise


def _record_version(key: str, record: dict, versions_path: str) -> None:
    """Set one key under the file lock, so two writers keep both updates."""
    path = Path(versions_path)
    with _file_lock(path.with_name(f".{path.name}.lock")):
        versions = _load_versions(versions_path)
        versions[key] = record
        _save_versions(versions, versions_path)


def _staging_dir(cache_dir: Path) -> tempfile.TemporaryDirectory:
    """Scratch space beside the cache, on its filesystem.

    /tmp is a 4 GB tmpfs here: staging there filled it and turned the
    promotion into a copy, during which the cache held a partial tree.
    """
    cache_dir.parent.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(
        dir=cache_dir.parent, prefix=f".{cache_dir.name}-"
    )


def _promote(extract_dir: Path, cache_dir: Path, scratch: Path) -> None:
    """Swap the new tree in by renames alone.

    The old tree steps aside into the run's own scratch directory, never a
    fixed sibling name another run could be using, and comes back if the
    new one cannot be moved in.
    """
    previous = scratch / "previous"
    if cache_dir.exists():
        os.replace(cache_dir, previous)
    try:
        os.replace(extract_dir, cache_dir)
    except BaseException:
        if previous.exists() and not cache_dir.exists():
            os.replace(previous, cache_dir)
        raise


def _api_request(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )
    token = github_token()
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
        log.warning(
            "failed to fetch remote SHA for %s/%s@%s: %s", owner, repo, version, exc
        )
        return None


class NothingExtractedError(Exception):
    """An archive that yields no file for the cache.

    Promoting it replaced the cache with an empty directory, recorded the new
    version and reported success, so the next run read "up to date" and the
    packs left without the directory.
    """


def _is_safe_tar_member(member: tarfile.TarInfo, dest: Path) -> bool:
    """Reject path traversal, absolute paths, and symlinks in tar members."""
    if member.issym() or member.islnk():
        return False
    if member.name.startswith("/") or ".." in member.name.split("/"):
        return False
    resolved = (dest / member.name).resolve()
    dest_str = str(dest.resolve()) + os.sep
    if not str(resolved).startswith(dest_str) and str(resolved) != str(dest.resolve()):
        return False
    return True


def _download_and_extract(
    source_url: str,
    source_path: str,
    local_cache: str,
    exclude: list[str] | None = None,
    measured: Callable[[int], None] | None = None,
) -> int:
    """Download tarball, extract source_path subtree to local_cache.

    Returns the number of files extracted. measured receives the size of
    the archive downloaded.
    """
    exclude = exclude or []
    cache_dir = Path(local_cache)

    with _staging_dir(cache_dir) as tmpdir:
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
        if measured is not None:
            measured(tarball_path.stat().st_size)

        log.info("extracting %s -> %s", source_path, local_cache)

        prefix = source_path.rstrip("/") + "/"
        file_count = 0

        with tarfile.open(tarball_path, "r:gz") as tf:
            extract_dir = Path(tmpdir) / "extract"
            extract_dir.mkdir()

            for member in tf.getmembers():
                if not member.name.startswith(prefix) and member.name != source_path:
                    continue

                rel = member.name[len(prefix) :]
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

        if not file_count:
            raise NothingExtractedError(f"no file under {source_path} in the archive")
        _promote(extract_dir, cache_dir, Path(tmpdir))

    return file_count


def _download_and_extract_zip(
    source_url: str,
    local_cache: str,
    exclude: list[str] | None = None,
    strip_components: int = 0,
    measured: Callable[[int], None] | None = None,
) -> int:
    """Download ZIP, extract to local_cache. Returns file count.

    strip_components removes N leading path components from each entry
    (like tar --strip-components). Useful when a ZIP has a single root
    directory that should be flattened.
    """
    exclude = exclude or []
    cache_dir = Path(local_cache)

    with _staging_dir(cache_dir) as tmpdir:
        zip_path = Path(tmpdir) / "archive.zip"
        log.info("downloading %s", source_url)

        req = urllib.request.Request(source_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            with open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
        if measured is not None:
            measured(zip_path.stat().st_size)

        extract_dir = Path(tmpdir) / "extract"
        extract_dir.mkdir()
        file_count = 0

        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if ".." in name or name.startswith("/"):
                    continue
                # strip leading path components
                parts = name.split("/")
                if strip_components > 0:
                    if len(parts) <= strip_components:
                        continue
                    parts = parts[strip_components:]
                    name = "/".join(parts)
                # skip excludes (check against stripped path)
                top = parts[0] if parts else ""
                if top in exclude:
                    continue
                dest = extract_dir / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                file_count += 1

        if not file_count:
            raise NothingExtractedError("the archive holds no file to extract")
        # The old tree is stepped aside rather than deleted: removing it
        # first and then failing to move the new one in left the cache with
        # nothing at all, and the next run reads that as "never fetched".
        _promote(extract_dir, cache_dir, Path(tmpdir))

    return file_count


def _measure_archive(source_url: str) -> int | None:
    """The size of the archive at source_url, read by streaming it: a
    tarball GitHub builds on request is sent without a Content-Length."""
    req = urllib.request.Request(source_url, headers={"User-Agent": USER_AGENT})
    size = 0
    try:
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            while chunk := resp.read(65536):
                size += len(chunk)
    except _TRANSIENT as exc:
        log.warning("could not measure %s: %s", source_url, exc)
        return None
    return size or None


def _record_archive_size(key: str, entry: dict, versions_path: str) -> None:
    """Record the archive size of a tree current since before it was kept.

    The installer announces a tree's download as that size: a tarball
    whose tree is 10 KB is a download of 21 MB. Measured, not refetched,
    so the tree the packs carry stays the one recorded.
    """
    path = Path(versions_path)
    with _file_lock(path.with_name(f".{path.name}.lock")):
        versions = _load_versions(versions_path)
        record = versions.get(key)
        if record is None or "archive_size" in record:
            return
    version = entry.get("version", "master")
    size = _measure_archive(entry["source_url"].format(version=version))
    if size is None:
        return
    with _file_lock(path.with_name(f".{path.name}.lock")):
        versions = _load_versions(versions_path)
        if key in versions and "archive_size" not in versions[key]:
            versions[key]["archive_size"] = size
            _save_versions(versions, versions_path)
    log.info("[%s] archive size recorded: %d bytes", key, size)


def _get_remote_etag(source_url: str) -> str | None:
    """HEAD request to get ETag or Last-Modified for freshness check."""
    try:
        req = urllib.request.Request(
            source_url, method="HEAD", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.headers.get("ETag") or resp.headers.get("Last-Modified") or ""
    except (urllib.error.URLError, OSError):
        return None


def _short_tag(tag: str | None) -> str:
    """A commit sha or ETag cut for a log line, quotes dropped first: a
    quoted ETag cut at 12 characters kept its opening quote only."""
    if not tag:
        return "none"
    return tag.strip().removeprefix("W/").strip('"')[:12] or "none"


def refresh_entry(
    key: str,
    entry: dict,
    *,
    force: bool = False,
    dry_run: bool = False,
    versions_path: str = VERSIONS_FILE,
) -> bool | None:
    """Refresh a single data directory entry.

    Returns True if the entry was refreshed (or would be in dry-run mode).
    The decision and the swap run under one lock per directory: a run that
    waited for another session re-reads the version it recorded and finds
    nothing left to do.

    The exclusive lock waits for every reader, and a pipeline reads the
    trees for its whole run: a second build sat on "waiting" for a tree the
    remote check would have found current. The check is made first without
    it, and only a tree to replace waits.
    """
    if dry_run:
        return _refresh_entry(key, entry, force, dry_run, versions_path)
    if not force:
        needs, _remote, cached_tag = _decide(key, entry, False, versions_path)
        if needs is None:
            return None
        if not needs:
            log.info("[%s] up to date (tag: %s)", key, _short_tag(cached_tag))
            _record_archive_size(key, entry, versions_path)
            return False
    with cache_lock(entry["local_cache"]):
        return _refresh_entry(key, entry, force, dry_run, versions_path)


def _decide(
    key: str, entry: dict, force: bool, versions_path: str
) -> tuple[bool | None, str | None, str | None]:
    """(whether the tree needs a refresh, the remote tag read, the recorded
    tag). None when the remote could not be read."""
    version = entry.get("version", "master")
    cached = _load_versions(versions_path).get(key, {})
    cached_tag = cached.get("sha") or cached.get("etag")
    if force or not Path(entry["local_cache"]).exists():
        return True, None, cached_tag
    if entry.get("source_type", "tarball") == "zip":
        remote_tag = _get_remote_etag(entry["source_url"].format(version=version))
    else:
        remote_tag = get_remote_sha(entry["source_url"], version)
    if remote_tag is None:
        log.warning("[%s] could not check remote, skipping", key)
        return None, None, cached_tag
    return remote_tag != cached_tag, remote_tag, cached_tag


def _refresh_entry(
    key: str, entry: dict, force: bool, dry_run: bool, versions_path: str
) -> bool | None:
    source_type = entry.get("source_type", "tarball")
    version = entry.get("version", "master")
    source_url = entry["source_url"].format(version=version)
    local_cache = entry["local_cache"]
    exclude = entry.get("exclude", [])

    needs_refresh, remote_tag, cached_tag = _decide(key, entry, force, versions_path)
    if needs_refresh is None:
        return None
    if not needs_refresh:
        log.info("[%s] up to date (tag: %s)", key, _short_tag(cached_tag))
        return False

    if dry_run:
        if remote_tag is not None:
            reason = f"cached: {_short_tag(cached_tag)}, remote: {_short_tag(remote_tag)}"
        elif force:
            reason = "forced"
        else:
            reason = "not cached"
        log.info("[%s] would refresh (type: %s, %s)", key, source_type, reason)
        return True

    if remote_tag is None:
        # Read before the download. A release published in between then
        # leaves an older tag on newer content, which the next run refreshes.
        # Read after, it left a newer tag on older content, trusted for good.
        if source_type == "zip":
            remote_tag = _get_remote_etag(source_url)
        else:
            remote_tag = get_remote_sha(entry["source_url"], version)

    archive_sizes: list[int] = []

    def fetch() -> int:
        archive_sizes.clear()
        if source_type == "zip":
            return _download_and_extract_zip(
                source_url, local_cache, exclude, entry.get("strip_components", 0),
                measured=archive_sizes.append,
            )
        source_path = entry["source_path"].format(version=version)
        return _download_and_extract(
            source_url, source_path, local_cache, exclude, measured=archive_sizes.append
        )

    # An archive that reads but holds nothing under the path is the same on
    # every try: only a failed or unreadable download is tried again.
    for attempt, wait in enumerate((*DOWNLOAD_RETRY_WAITS, None), start=1):
        try:
            file_count = fetch()
            break
        except NothingExtractedError as exc:
            log.warning("[%s] download failed: %s", key, exc)
            return None
        except _TRANSIENT as exc:
            if wait is None:
                log.warning("[%s] download failed after %d tries: %s", key, attempt, exc)
                return None
            log.warning("[%s] download failed (%s), trying again in %d s", key, exc, wait)
            time.sleep(wait)

    record = {"sha": remote_tag or "", "version": version}
    if archive_sizes:
        record["archive_size"] = archive_sizes[-1]
    _record_version(key, record, versions_path)

    log.info("[%s] refreshed: %d files extracted to %s", key, file_count, local_cache)
    return True


def refresh_all(
    registry: dict[str, dict],
    *,
    force: bool = False,
    dry_run: bool = False,
    versions_path: str = VERSIONS_FILE,
    platform: str | None = None,
) -> dict[str, bool | None]:
    """Refresh all entries in the registry.

    If platform is set, only refresh entries whose for_platforms
    includes that platform (or entries with no for_platforms restriction).
    Returns a dict mapping key -> True when refreshed, False when already up
    to date, None when the refresh failed. A single boolean conflated the last
    two, so a run that reached no remote at all exited 0 like a run with
    nothing to do.
    """
    results = {}
    for key, entry in registry.items():
        allowed = entry.get("for_platforms")
        if platform and allowed and platform not in allowed:
            continue
        results[key] = refresh_entry(
            key,
            entry,
            force=force,
            dry_run=dry_run,
            versions_path=versions_path,
        )
    if any(results.values()):
        # A cache the resolver indexed in this process has changed under it.
        from common import forget_data_dir_index  # noqa: PLC0415

        forget_data_dir_index()
    return results


def summarize(outcomes: dict[str, bool | None], dry_run: bool) -> str:
    """One closing line: how many entries changed, were current, failed."""
    refreshed = sum(1 for o in outcomes.values() if o is True)
    current = sum(1 for o in outcomes.values() if o is False)
    failed = sum(1 for o in outcomes.values() if o is None)
    verb = "would refresh" if dry_run else "refreshed"
    line = f"{len(outcomes)} entries: {refreshed} {verb}, {current} up to date"
    return f"{line}, {failed} failed" if failed else line


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Refresh cached data directories from upstream"
    )
    parser.add_argument("--key", help="Refresh only this entry")
    parser.add_argument(
        "--force", action="store_true", help="Re-download even if up to date"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without downloading"
    )
    parser.add_argument(
        "--platform", "-p", type=platform_arg, help="Only refresh entries for this platform"
    )
    parser.add_argument(
        "--registry", default=DEFAULT_REGISTRY, help="Path to _data_dirs.yml"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    if args.platform:
        # The registry sits in the platforms directory it serves.
        require_platform(args.platform, os.path.dirname(args.registry) or ".")
    registry = load_registry(args.registry)

    if args.key:
        if args.key not in registry:
            log.error("unknown key: %s. %s", args.key, suggest_names([args.key], list(registry), "--dry-run"))
            raise SystemExit(1)
        allowed = registry[args.key].get("for_platforms")
        if args.platform and allowed and args.platform not in allowed:
            # The platform restriction applied only without --key: dolphin-sys
            # was refreshed for RomM, which never reads it.
            log.error(
                "%s does not serve %s (for_platforms: %s)",
                args.key, args.platform, ", ".join(allowed),
            )
            raise SystemExit(2)
        outcomes = {
            args.key: refresh_entry(
                args.key, registry[args.key], force=args.force, dry_run=args.dry_run
            )
        }
    else:
        outcomes = refresh_all(
            registry, force=args.force, dry_run=args.dry_run, platform=args.platform
        )

    log.info(summarize(outcomes, args.dry_run))
    failed = sorted(key for key, outcome in outcomes.items() if outcome is None)
    if failed:
        log.error("refresh failed: %s", ", ".join(failed))
        raise SystemExit(1)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
