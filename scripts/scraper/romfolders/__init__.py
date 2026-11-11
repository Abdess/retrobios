"""Scrape each setup's rom folders from its own source, at a pinned revision.

`platforms/romfolders/_sources/<setup>.yml` names the repositories and
the commits to read, the format of the system list, and the facts a parser
cannot read from a table (roms root, case rule, folders the OS never scans),
each with its `source_ref`. A format parser reads the system list and returns
one row per folder. The setup file it writes carries the OS's own names only:
`scripts/romfolders.py` resolves them to repository systems and profiles.

Every fetch goes through `upstream.fetch_file`, cached by revision, so a
second run reads nothing from the network and writes the same bytes.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

_SCRIPTS_DIR = str(Path(__file__).resolve().parents[2])
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import upstream  # noqa: E402
from safeparse import yaml_load  # noqa: E402

CACHE_DIR = upstream.CACHE_DIR

# Keys a setup file carries, in the order they are written.
SETUP_KEYS = (
    "setup", "name", "platform", "sources", "roms_root", "case_sensitive",
    "case_ref", "skip", "hidden", "media", "notes", "folders",
)
ROW_KEYS = (
    "folder", "name", "aliases", "extensions", "files", "core", "emulator", "source_ref",
    "board_defaults", "arcade", "searched_by", "note",
)


class SourceError(RuntimeError):
    """A pinned file is absent, or its content no longer has the shape read."""


@dataclass
class Fetcher:
    """Reads pinned files of one setup's declared sources."""

    sources: dict[str, dict]
    cache_dir: str = CACHE_DIR
    offline: bool = False
    _cached_dirs: dict[str, dict[str, set[str]]] = field(default_factory=dict, init=False, repr=False)

    def _repo(self, key: str) -> tuple[upstream.Repo, str]:
        if key not in self.sources:
            raise SourceError(f"source {key!r} is not declared")
        spec = self.sources[key]
        repo = upstream.parse_repo(spec["repo"])
        if repo is None:
            raise SourceError(f"source {key!r}: unsupported forge {spec['repo']}")
        return repo, spec["commit"]

    def text(self, key: str, path: str) -> str:
        """One file at the pinned commit, or SourceError when absent."""
        repo, sha = self._repo(key)
        lines = upstream.fetch_file(repo, sha, path, self.cache_dir, self.offline)
        if lines is None:
            raise SourceError(f"{repo.slug}@{sha[:8]}:{path} does not exist")
        return "\n".join(lines) + "\n"

    def optional_text(self, key: str, path: str) -> str | None:
        repo, sha = self._repo(key)
        for directory, held in self._cached_dirs.get(key, {}).items():
            if path.startswith(directory + "/") and path not in held:
                return None
        lines = upstream.fetch_file(repo, sha, path, self.cache_dir, self.offline)
        return None if lines is None else "\n".join(lines) + "\n"

    def tree(self, key: str, prefix: str = "") -> list[str]:
        """Every blob path under a prefix at the pinned commit."""
        repo, sha = self._repo(key)
        if repo.family == "gitlab" and prefix.strip("/"):
            return self._gitlab_subtree(repo, sha, prefix)
        paths, truncated = upstream.list_tree(repo, sha, self.cache_dir, self.offline)
        if truncated:
            raise SourceError(f"{repo.slug}@{sha[:8]}: the forge truncated the tree")
        return sorted(p for p in paths if p.startswith(prefix))

    def cache_directory(self, key: str, directory: str) -> None:
        """Fetch a whole GitLab directory in one archive request before its
        files are read one by one. A no-op on other forges."""
        repo, sha = self._repo(key)
        held = upstream.cache_gitlab_directory(repo, sha, directory, self.cache_dir, self.offline)
        if held is not None:
            self._cached_dirs.setdefault(key, {})[directory.strip("/")] = held

    def entries(self, key: str, directory: str) -> list[str]:
        """Paths of the files and folders directly under one directory."""
        repo, sha = self._repo(key)
        held = self._cached_dirs.get(key, {}).get(directory.strip("/"))
        if held is not None:
            prefix = directory.strip("/") + "/"
            return sorted({prefix + p[len(prefix):].split("/", 1)[0] for p in held})
        if repo.family != "gitlab":
            prefix = directory.strip("/") + "/"
            return sorted({prefix + p[len(prefix):].split("/", 1)[0] for p in self.tree(key, prefix)})
        return self._gitlab_listing(repo, sha, directory, recursive=False, blobs=False)

    def _gitlab_subtree(self, repo: upstream.Repo, sha: str, prefix: str) -> list[str]:
        """GitLab pages its tree 100 entries at a time and Recalbox's whole
        tree outruns the page cap: list only the directory asked for."""
        paths = self._gitlab_listing(repo, sha, prefix, recursive=True, blobs=True)
        return sorted(p for p in paths if p.startswith(prefix))

    def _gitlab_listing(
        self, repo: upstream.Repo, sha: str, directory: str, *, recursive: bool, blobs: bool
    ) -> list[str]:
        directory = directory.strip("/")
        paths: list[str] = []
        for page in range(1, upstream.MAX_TREE_PAGES + 1):
            url = (
                f"{repo.api_base}/projects/{upstream._project(repo)}/repository/tree"
                f"?ref={sha}&path={directory}&recursive={'true' if recursive else 'false'}"
                f"&per_page={upstream.TREE_PAGE_SIZE}&page={page}"
            )
            payload = upstream._api(url, self.cache_dir, self.offline)
            if not isinstance(payload, list):
                raise SourceError(f"{repo.slug}@{sha[:8]}: {directory} could not be listed")
            paths.extend(
                entry["path"] for entry in payload
                if isinstance(entry, dict) and entry.get("path")
                and (entry.get("type") == "blob" or not blobs)
            )
            if len(payload) < upstream.TREE_PAGE_SIZE:
                return sorted(paths)
        raise SourceError(f"{repo.slug}@{sha[:8]}: {directory} outruns the page cap")


Parser = Callable[[dict, Fetcher], list[dict]]
FORMATS: dict[str, Parser] = {}


def register(name: str) -> Callable[[Parser], Parser]:
    def wrap(func: Parser) -> Parser:
        if name in FORMATS:
            raise ValueError(f"format {name!r} registered twice")
        FORMATS[name] = func
        return func

    return wrap


def load_formats() -> dict[str, Parser]:
    """Import every parser module of this package once."""
    if not FORMATS:
        for info in pkgutil.iter_modules([str(Path(__file__).parent)]):
            if not info.name.startswith("_"):
                importlib.import_module(f"{__name__}.{info.name}")
    return FORMATS


def load_sources(directory: Path) -> dict[str, dict]:
    """Each setup's declared sources and facts, keyed by its file name."""
    out: dict[str, dict] = {}
    for path in sorted(Path(directory).glob("*.yml")):
        with path.open(encoding="utf-8") as handle:
            out[path.stem] = yaml_load(handle) or {}
    return out


def _clean_row(row: dict) -> dict:
    unknown = set(row) - set(ROW_KEYS)
    if unknown:
        raise ValueError(f"folder {row.get('folder')!r}: unknown keys {sorted(unknown)}")
    out = {key: row[key] for key in ROW_KEYS if row.get(key) not in (None, [], {}, "")}
    if out.get("name") == out["folder"]:
        del out["name"]
    if "extensions" in out:
        out["extensions"] = sorted({e.lower() for e in out["extensions"]})
    if "aliases" in out:
        out["aliases"] = sorted(set(out["aliases"]) - {out["folder"]})
        if not out["aliases"]:
            del out["aliases"]
    return out


def scrape_setup(setup: str, spec: dict, fetcher: Fetcher) -> dict:
    """The setup document: declared facts, then the parsed folders."""
    formats = load_formats()
    fmt = spec.get("format")
    rows: list[dict] = []
    if fmt:
        if fmt not in formats:
            raise SourceError(f"{setup}: no parser for format {fmt!r}")
        rows = formats[fmt](spec, fetcher)
        if not rows and not spec.get("allow_empty"):
            raise SourceError(f"{setup}: format {fmt} read no folder")
    folders: dict[str, dict] = {}
    for row in rows:
        clean = _clean_row(row)
        key = clean["folder"]
        if key in folders:
            raise SourceError(f"{setup}: folder {key!r} read twice")
        folders[key] = clean
    doc = {"setup": setup, **{k: spec[k] for k in SETUP_KEYS[1:-1] if k in spec}}
    doc["folders"] = [folders[k] for k in sorted(folders, key=lambda f: (f.lower(), f))]
    return doc
