"""The platforms' own files an export patches: where each is read, at which
revision, and the cache that keeps them with the URL they came from."""

from __future__ import annotations

import contextlib
import functools
import http.client
import json
import re
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

from core.artifacts import file_lock, write_bytes_atomic, write_text_atomic
from core.cli import InputMissing
from model.sourcerevision import source_revision
from scraper.base_scraper import fetch_bytes
from .base_exporter import BaseExporter

DEFAULT_CACHE = ".cache/upstream-native"
SOURCES_INDEX = ".sources.json"
_USER_AGENT = "retrobios-exporter/1.0"
_MAX_BYTES = 64 * 1024 * 1024


class SourcesIndexUnreadable(InputMissing):
    """The cache's URL index exists and does not read as JSON."""


def _load_sources(index: Path | None) -> dict[str, str]:
    """The URL each cached file was fetched from.

    An absent index records nothing. An index that does not read raises:
    read as empty it let every cached original pass for current, and the
    next download rewrote it with that one entry.
    """
    if index is None or not index.is_file():
        return {}
    try:
        return json.loads(index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourcesIndexUnreadable(
            f"{index} does not read ({exc}): remove it, then"
            " python scripts/export_native.py --all --refresh-cache"
            " downloads every original again and records its URL"
        ) from exc


def source_key(destination: Path, index: Path | None) -> str:
    """How the index names a cached file: its path below the cache root.

    A key that repeated the cache directory as it was typed changed with the
    working directory, and a file recorded from one place looked unrecorded
    from another.
    """
    if index is not None:
        try:
            return destination.resolve().relative_to(index.parent.resolve()).as_posix()
        except ValueError:
            pass
    return str(destination)


def load_sources(upstream_dir: Path) -> dict[str, str]:
    """Cached file -> URL it was fetched from, for a whole cache directory."""
    return _load_sources(upstream_dir / SOURCES_INDEX)


class OriginalUnreadable(ValueError):
    """A platform's file that is not what its format says it is."""


def _read_archive(unpack: Callable[[bytes], dict[str, str]], payload: bytes) -> dict[str, str]:
    """Unpack an original, naming the remedy when its bytes are not one."""
    try:
        return unpack(payload)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, zlib.error, KeyError) as exc:
        raise OriginalUnreadable(
            f"archive unreadable ({exc}): --refresh-cache downloads it again"
        ) from exc


def _read_text(payload: bytes) -> str:
    """A text original, refused when it cannot be the platform's file.

    An empty body or an HTML error page served with 200 parsed as a file
    with no entries, and four exporters rebuilt the platform's file from our
    data alone and said OK: libretro's quoted names and Recalbox's comments
    were gone.
    """
    text = payload.decode("utf-8", errors="replace")
    head = text.lstrip()[:64].lower()
    if not head:
        raise OriginalUnreadable("empty file: --refresh-cache downloads it again")
    if head.startswith(("<!doctype html", "<html")):
        raise OriginalUnreadable(
            "an HTML page, not the platform's file: --refresh-cache downloads it again"
        )
    return text


def fetch(
    url: str,
    destination: Path,
    index: Path | None = None,
    refresh: bool = False,
    check: Callable[[bytes], object] | None = None,
) -> bytes:
    """Download an original once, then read it from the cache.

    The cache path carries the file's own name and nothing of the revision it
    came from, so a file fetched under one pin was served under every later
    one and pinned_base() stopped having any effect after the first run. The
    URL that produced each cached file is recorded beside the cache, and a
    different URL refetches. A cache written before this index existed keeps
    being served: nothing recorded means nothing contradicted.

    A branch URL names no revision, so the same URL serves new bytes after
    the platform moves. refresh downloads again whatever the cache holds:
    it is what a rescrape calls, so the original and its transcription
    describe the same moment.
    """
    key = source_key(destination, index)

    def locked() -> contextlib.AbstractContextManager[object]:
        # The bytes and the URL that names them change together: written
        # under two locks, two runs wanting two URLs for one path could leave
        # one's bytes beside the other's index entry, and the wrong revision
        # was then served as current.
        if index is None:
            return contextlib.nullcontext()
        index.parent.mkdir(parents=True, exist_ok=True)
        return file_lock(index.with_name(f".{index.name}.lock"))

    with locked():
        if (
            not refresh
            and destination.exists()
            and _load_sources(index).get(key, url) == url
        ):
            return destination.read_bytes()
    try:
        payload = fetch_bytes(
            url, {"User-Agent": _USER_AGENT}, timeout=60, max_bytes=_MAX_BYTES
        )
    except ValueError as exc:
        raise OriginalUnreadable(f"{url}: response larger than {_MAX_BYTES} bytes") from exc
    # An error page served with 200 replaced a good archive and was then
    # served on every run: what does not read is never cached.
    if check is not None:
        check(payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with locked():
        write_bytes_atomic(str(destination), payload)
        if index is not None:
            # Platforms refresh in parallel: the index is read again under
            # the lock, or the last writer erased what the others recorded.
            recorded = _load_sources(index)
            recorded[key] = url
            write_text_atomic(
                str(index), json.dumps(recorded, indent=2, sort_keys=True) + "\n"
            )
    return payload


def pinned_base(wanted: dict[str, str], scraped: dict | None) -> str:
    """The revision our transcription came from, when the YAML records it.

    A scraper pins a stable tag (batocera-43.1, BizHawk 2.11.1) and writes
    that URL into the platform YAML. Patching the branch tip instead would
    correct a file our data never described.
    """
    source = _raw_url(str((scraped or {}).get("source", "")))
    tree = _GITHUB_TREE.match(source)
    if tree:
        # RetroDECK reads one manifest per component: the YAML records the
        # tree at the commit read, and every file is taken at that commit.
        return "https://raw.githubusercontent.com/{}/{}/{}/".format(*tree.groups())
    for relative in wanted:
        if source.endswith("/" + relative):
            return source[: -len(relative)]
    return ""


_GITHUB_TREE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/tree/([0-9a-f]{40})/?$")


def _raw_url(url: str) -> str:
    """A GitHub blob page names a revision but serves HTML, raw serves bytes."""
    marker = "/blob/"
    if url.startswith("https://github.com/") and marker in url:
        owner_repo, _, path = url[len("https://github.com/") :].partition(marker)
        return f"https://raw.githubusercontent.com/{owner_repo}/{path}"
    return url


def wanted_sources(
    exporter: BaseExporter, systems: dict, scraped: dict | None = None
) -> dict[str, str]:
    """Cache-relative name -> URL of every file the exporter patches."""
    wanted = dict(exporter.native_sources())
    components = getattr(exporter, "components", None)
    component_url = getattr(exporter, "component_url", None)
    if callable(components) and callable(component_url):
        for component in components(systems):
            wanted[f"{component}/component_manifest.json"] = component_url(
                component
            )

    base = pinned_base(wanted, scraped)
    if base:
        wanted = {
            relative: _at_revision(wanted[relative], base) or base + relative
            for relative in wanted
        }
    source = str((scraped or {}).get("source", ""))
    return {
        relative: _tarball_at(url, source) or url for relative, url in wanted.items()
    }


def unpinned(wanted: dict[str, str], scraped: dict | None) -> list[str]:
    """Every file the export would read off the revision the YAML records.

    pinned_base() returned '' when the source named no revision or no
    longer ended in the file, and the exporter's own branch URL was then
    patched without a word: a file our transcription never described.
    """
    source = str((scraped or {}).get("source", ""))
    revision = source_revision(source)
    if not revision:
        return [f"the platform's source names no revision ({source or 'none'}): rescrape it"]
    return [
        f"{relative} would be read at {url}, not at {revision}: rescrape the platform"
        for relative, url in wanted.items()
        if f"/{revision}/" not in url and not url.endswith(f"/{revision}")
    ]


_CODELOAD = re.compile(r"^https://codeload\.github\.com/([^/]+)/([^/]+)/tar\.gz/")


def _tarball_at(url: str, source: str) -> str:
    """The recorded tarball when the original is a tarball of the same repository.

    RetroPie's declarations are spread over every scriptmodule, so its scraper
    reads the repository archive. The archive the YAML records is the one at
    the commit it was read from, the exporter's own URL names the branch.
    """
    wanted, recorded = _CODELOAD.match(url), _CODELOAD.match(source)
    if wanted and recorded and wanted.group(1, 2) == recorded.group(1, 2):
        return source
    return ""


_RAW_GITHUB = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/")


def _at_revision(url: str, base: str) -> str:
    """A file of the pinned repository, read at the pinned revision, empty
    when the URL is not a raw GitHub URL of that repository.

    ROCKNIX's checker sits in packages/rocknix/, the emulators it names in
    packages/virtual/: no shared directory, one revision.
    """
    pinned, other = _RAW_GITHUB.match(base), _RAW_GITHUB.match(url)
    if pinned and other and pinned.group(1, 2) == other.group(1, 2):
        return pinned.group(0) + url[other.end():]
    return ""


def collect_originals(
    exporter: BaseExporter,
    systems: dict,
    upstream_dir: Path,
    allow_fetch: bool,
    scraped: dict | None = None,
    refresh: bool = False,
) -> tuple[dict[str, str], list[str]]:
    """Gather the platform's own files, from disk or from upstream.

    With fetching on, an existing file still goes through fetch(): reading
    it straight from disk skipped the recorded URL, so a file cached under
    one pin kept being patched after the platform YAML moved to the next.
    """
    wanted = wanted_sources(exporter, systems, scraped)
    root = upstream_dir / exporter.platform_name()
    index = upstream_dir / SOURCES_INDEX
    originals: dict[str, str] = {}
    missing: list[str] = []
    unpack = getattr(exporter, "unpack", None)
    for relative, url in wanted.items():
        path = root / relative
        reader: Callable[[bytes], dict[str, str]] | None = (
            unpack if callable(unpack) and relative.endswith((".zip", ".tar.gz")) else None
        )
        check: Callable[[bytes], object] = (
            functools.partial(_read_archive, reader) if reader is not None else _read_text
        )
        try:
            if allow_fetch:
                payload = fetch(url, path, index, refresh, check)
            elif path.exists():
                payload = path.read_bytes()
            else:
                missing.append(
                    f"{relative}: not in {root}; rerun with --fetch to download it"
                )
                continue
            if reader is not None:
                originals.update(_read_archive(reader, payload))
                keep = getattr(exporter, "keep_archive", None)
                if callable(keep):
                    keep(relative, payload)
            else:
                originals[relative] = _read_text(payload)
        # One platform's unreadable file fails that platform: raised, it
        # stopped --all before the platforms after it.
        except (OSError, http.client.HTTPException, OriginalUnreadable) as exc:
            missing.append(f"{relative}: {exc}")

    return originals, missing
