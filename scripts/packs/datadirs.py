"""The cached data directories: the lock readers hold on them, and their refresh from upstream."""

from __future__ import annotations

import contextlib
import http.client
import json
import logging
import os
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

from core import upstream
from core import forgehttp
from core.artifacts import file_lock as _file_lock, write_text_atomic
from core.forgehttp import remote_etag as _get_remote_etag
from model.registry import load_versions, versions_file_for
from packs.datadirextract import extract_tar_subtree, extract_zip_tree


log = logging.getLogger(__name__)

USER_AGENT = "retrobios/1.0"
REQUEST_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 300
# A mirror sometimes answers with a page that is not the archive: the
# buildbot's ScummVM.zip failed CI once as "File is not a zip file" and
# downloaded fine minutes later. Seconds to wait before each retry. The
# transfer itself is retried by core.forgehttp.download: these waits cover
# an archive that arrived whole and does not read.
DOWNLOAD_RETRY_WAITS = (5, 20)
_TRANSIENT = (
    urllib.error.URLError, OSError, http.client.HTTPException,
    tarfile.TarError, zipfile.BadZipFile, EOFError,
)


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


def _save_versions(versions: dict[str, dict], versions_path: str | Path) -> None:
    """Write the version file whole or not at all.

    Truncating in place let a concurrent reader load an empty file and die
    on JSONDecodeError.
    """
    Path(versions_path).parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(versions_path, json.dumps(versions, indent=2, sort_keys=True) + "\n")


def _record_version(key: str, record: dict, versions_path: str | Path) -> None:
    """Set one key under the file lock, so two writers keep both updates."""
    path = Path(versions_path)
    with _file_lock(path.with_name(f".{path.name}.lock")):
        versions = load_versions(versions_path)
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


def revisioned(entry: dict) -> bool:
    """Whether the source names a forge revision: {version} in a GitHub or
    GitLab address. Such a tree is fetched at the commit its branch points
    to, recorded, and listed at that commit, whose bytes never change. Any
    other source (the buildbot's nightly assets, a release asset) names no
    revision: what it serves today is all it holds."""
    url = str(entry.get("source_url", ""))
    repo = upstream.parse_repo(url)
    return "{version}" in url and repo is not None and repo.family in ("github", "gitlab")


def get_remote_sha(source_url: str, version: str) -> str | None:
    """The commit a branch or tag of the source's repository points at now,
    asked of the forge each time and kept nowhere but the versions file."""
    repo = upstream.parse_repo(source_url)
    if repo is None:
        log.warning("cannot parse repo from URL: %s", source_url)
        return None
    try:
        return upstream.resolve_head(repo, None, branch=version)
    except (forgehttp.UpstreamError, ValueError) as exc:
        log.warning("failed to fetch remote SHA for %s@%s: %s", repo.slug, version, exc)
        return None


class NothingExtractedError(Exception):
    """An archive that yields no file for the cache.

    Promoting it replaced the cache with an empty directory, recorded the new
    version and reported success, so the next run read "up to date" and the
    packs left without the directory.
    """


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
    cache_dir = Path(local_cache)

    with _staging_dir(cache_dir) as tmpdir:
        tarball_path = Path(tmpdir) / "archive.tar.gz"
        _fetch(source_url, tarball_path, measured)

        log.info("extracting %s -> %s", source_path, local_cache)
        extract_dir = Path(tmpdir) / "extract"
        extract_dir.mkdir()
        file_count, skipped = extract_tar_subtree(
            tarball_path, extract_dir, source_path, exclude or []
        )
        for name in skipped:
            log.warning("skipping unsafe tar member: %s", name)

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
    cache_dir = Path(local_cache)

    with _staging_dir(cache_dir) as tmpdir:
        zip_path = Path(tmpdir) / "archive.zip"
        _fetch(source_url, zip_path, measured)

        extract_dir = Path(tmpdir) / "extract"
        extract_dir.mkdir()
        file_count = extract_zip_tree(zip_path, extract_dir, exclude or [], strip_components)

        if not file_count:
            raise NothingExtractedError("the archive holds no file to extract")
        # The old tree is stepped aside rather than deleted: removing it
        # first and then failing to move the new one in left the cache with
        # nothing at all, and the next run reads that as "never fetched".
        _promote(extract_dir, cache_dir, Path(tmpdir))

    return file_count


def _fetch(source_url: str, archive_path: Path, measured: Callable[[int], None] | None) -> None:
    """Download source_url to archive_path, its size handed to measured."""
    log.info("downloading %s", source_url)
    forgehttp.download(
        source_url, archive_path, timeout=DOWNLOAD_TIMEOUT, user_agent=USER_AGENT
    )
    if measured is not None:
        measured(archive_path.stat().st_size)


def _measure_archive(source_url: str) -> int | None:
    """The size of the archive at source_url, read by streaming it: a
    tarball GitHub builds on request is sent without a Content-Length."""
    req = urllib.request.Request(
        source_url, headers=forgehttp.forge_headers(source_url, user_agent=USER_AGENT)
    )

    def count(resp: http.client.HTTPResponse) -> int:
        size = 0
        while chunk := resp.read(65536):
            size += len(chunk)
        return size

    try:
        size = forgehttp.open_retrying(req, count, DOWNLOAD_TIMEOUT)
    except (*_TRANSIENT, forgehttp.UpstreamError) as exc:
        log.warning("could not measure %s: %s", source_url, exc)
        return None
    return size or None


def _record_archive_size(key: str, entry: dict) -> None:
    """Record the archive size of a tree current since before it was kept.

    The installer announces a tree's download as that size: a tarball
    whose tree is 10 KB is a download of 21 MB. Measured, not refetched,
    so the tree the packs carry stays the one recorded.
    """
    path = versions_file_for(entry)
    with _file_lock(path.with_name(f".{path.name}.lock")):
        versions = load_versions(path)
        record = versions.get(key)
        if record is None or "archive_size" in record:
            return
    # The archive of the commit the tree was fetched at, which the
    # install lists name, never the one its branch points to now.
    version = (record.get("sha") if revisioned(entry) and record.get("sha")
               else entry.get("version", "master"))
    size = _measure_archive(entry["source_url"].format(version=version))
    if size is None:
        return
    with _file_lock(path.with_name(f".{path.name}.lock")):
        versions = load_versions(path)
        if key in versions and "archive_size" not in versions[key]:
            versions[key]["archive_size"] = size
            _save_versions(versions, path)
    log.info("[%s] archive size recorded: %d bytes", key, size)


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
        return _refresh_entry(key, entry, force, dry_run)
    if not force:
        needs, _remote, cached_tag = _decide(key, entry, False)
        if needs is None:
            return None
        if not needs:
            log.info("[%s] up to date (tag: %s)", key, _short_tag(cached_tag))
            _record_archive_size(key, entry)
            return False
    with cache_lock(entry["local_cache"]):
        return _refresh_entry(key, entry, force, dry_run)


def _remote_tag(entry: dict, version: str) -> str | None:
    """The commit a revisioned source's branch points to, else the ETag of
    what the address serves."""
    if revisioned(entry):
        return get_remote_sha(entry["source_url"], version)
    return _get_remote_etag(entry["source_url"].format(version=version))


def _decide(
    key: str, entry: dict, force: bool
) -> tuple[bool | None, str | None, str | None]:
    """(whether the tree needs a refresh, the remote tag read, the recorded
    tag). None when the remote could not be read."""
    version = entry.get("version", "master")
    cached = load_versions(versions_file_for(entry)).get(key, {})
    cached_tag = cached.get("sha") or cached.get("etag")
    if force or not Path(entry["local_cache"]).exists():
        return True, None, cached_tag
    remote_tag = _remote_tag(entry, version)
    if remote_tag is None:
        log.warning("[%s] could not check remote, skipping", key)
        return None, None, cached_tag
    return remote_tag != cached_tag, remote_tag, cached_tag


def _refresh_entry(
    key: str, entry: dict, force: bool, dry_run: bool
) -> bool | None:
    source_type = entry.get("source_type", "tarball")
    version = entry.get("version", "master")
    source_url = entry["source_url"].format(version=version)
    local_cache = entry["local_cache"]
    exclude = entry.get("exclude", [])

    needs_refresh, remote_tag, cached_tag = _decide(key, entry, force)
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
        remote_tag = _remote_tag(entry, version)
    # A branch is fetched at the commit read above, never at its name: read
    # by name, a push in between left the recorded commit on other bytes,
    # and the list the installer checks named a revision it never had.
    at = remote_tag if revisioned(entry) and remote_tag else version
    source_url = entry["source_url"].format(version=at)

    archive_sizes: list[int] = []

    def fetch() -> int:
        archive_sizes.clear()
        if source_type == "zip":
            return _download_and_extract_zip(
                source_url, local_cache, exclude, entry.get("strip_components", 0),
                measured=archive_sizes.append,
            )
        source_path = entry["source_path"].format(version=at)
        return _download_and_extract(
            source_url, source_path, local_cache, exclude, measured=archive_sizes.append
        )

    # An archive that reads but holds nothing under the path, or a member
    # core.ziptools refuses (ValueError), is the same on every try: only a
    # failed or unreadable download is tried again.
    for attempt, wait in enumerate((*DOWNLOAD_RETRY_WAITS, None), start=1):
        try:
            file_count = fetch()
            break
        except (NothingExtractedError, ValueError, forgehttp.UpstreamError) as exc:
            # A host gone or still rate limited after core.upstream's own
            # waits answers the same way on the next try.
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
    _record_version(key, record, versions_file_for(entry))

    log.info("[%s] refreshed: %d files extracted to %s", key, file_count, local_cache)
    return True


def refresh_all(
    registry: dict[str, dict],
    *,
    force: bool = False,
    dry_run: bool = False,
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
        )
    if any(results.values()):
        # A cache the resolver indexed in this process has changed under it.
        from resolve.datadirs import forget_data_dir_index

        forget_data_dir_index()
    return results


def refresh_keys(
    registry: dict[str, dict],
    keys: list[str],
    *,
    force: bool = False,
) -> list[str]:
    """Refresh the named entries of a registry and return the keys whose
    refresh failed."""
    failed: list[str] = []
    refreshed = False
    for key in keys:
        log.info("refreshing %s ...", key)
        outcome = refresh_entry(key, registry[key], force=force)
        if outcome is None:
            log.error("refresh of %s failed", key)
            failed.append(key)
        refreshed = refreshed or bool(outcome)
    if refreshed:
        from resolve.datadirs import forget_data_dir_index

        forget_data_dir_index()
    return failed


def summarize(outcomes: dict[str, bool | None], dry_run: bool) -> str:
    """One closing line: how many entries changed, were current, failed."""
    refreshed = sum(1 for o in outcomes.values() if o is True)
    current = sum(1 for o in outcomes.values() if o is False)
    failed = sum(1 for o in outcomes.values() if o is None)
    verb = "would refresh" if dry_run else "refreshed"
    line = f"{len(outcomes)} entries: {refreshed} {verb}, {current} up to date"
    return f"{line}, {failed} failed" if failed else line
