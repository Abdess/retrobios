"""Access to upstream source repositories.

Resolves revisions, fetches files by sha, and compares trees across the
forge families the emulator profiles point at. Knows nothing about profile
structure.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

USER_AGENT = "retrobios-profile-sync/1.0"
ABSENT = "\0absent\0"
GITHUB_COMPARE_CAP = 300
RETRIES = 3
RETRY_BACKOFF = (0.5, 2.0)
GITHUB_HOSTS = frozenset(
    {"github.com", "api.github.com", "raw.githubusercontent.com"}
)

_HOSTS: dict[str, tuple[str, str, str]] = {
    "github.com": (
        "github",
        "https://api.github.com",
        "https://raw.githubusercontent.com",
    ),
    "gitlab.com": ("gitlab", "https://gitlab.com/api/v4", "https://gitlab.com"),
    "codeberg.org": (
        "forgejo",
        "https://codeberg.org/api/v1",
        "https://codeberg.org",
    ),
    "git.citron-emu.org": (
        "forgejo",
        "https://git.citron-emu.org/api/v1",
        "https://git.citron-emu.org",
    ),
    "git.eden-emu.dev": (
        "forgejo",
        "https://git.eden-emu.dev/api/v1",
        "https://git.eden-emu.dev",
    ),
}


_sleep = time.sleep


class UpstreamError(Exception):
    """Any failure while talking to a forge."""


class RateLimitError(UpstreamError):
    """The forge refused the request for quota reasons."""


@dataclass(frozen=True)
class Repo:
    host: str
    family: str
    api_base: str
    raw_base: str
    owner: str
    name: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class Release:
    tag: str
    date: str
    is_prerelease: bool


@dataclass(frozen=True)
class FileChange:
    status: str
    path: str
    previous_path: str | None


@dataclass(frozen=True)
class CompareResult:
    files: list[FileChange]
    truncated: bool


def parse_repo(url: str) -> Repo | None:
    """Build a Repo from a forge URL, or None when the host is unknown."""
    if not url:
        return None
    parts = urllib.parse.urlsplit(url.strip())
    entry = _HOSTS.get(parts.netloc)
    if entry is None:
        return None
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) < 2:
        return None
    owner, name = segments[0], segments[1]
    if name.endswith(".git"):
        name = name[:-4]
    family, api_base, raw_base = entry
    return Repo(parts.netloc, family, api_base, raw_base, owner, name)


def make_repo(host: str, owner: str, name: str) -> Repo | None:
    """Rebuild a Repo from a host and slug already known to be supported."""
    entry = _HOSTS.get(host)
    if entry is None:
        return None
    family, api_base, raw_base = entry
    return Repo(host, family, api_base, raw_base, owner, name)


def raw_url(repo: Repo, sha: str, path: str) -> str:
    """URL serving the raw bytes of one path at one revision."""
    quoted = urllib.parse.quote(path)
    if repo.family == "github":
        return f"{repo.raw_base}/{repo.owner}/{repo.name}/{sha}/{quoted}"
    if repo.family == "gitlab":
        return f"{repo.raw_base}/{repo.owner}/{repo.name}/-/raw/{sha}/{quoted}"
    return f"{repo.raw_base}/{repo.owner}/{repo.name}/raw/commit/{sha}/{quoted}"


def _headers(url: str, accept_json: bool = False) -> dict[str, str]:
    """Request headers. GITHUB_TOKEN is only ever sent to GitHub."""
    headers = {"User-Agent": USER_AGENT}
    if accept_json:
        headers["Accept"] = "application/json"
    token = os.environ.get("GITHUB_TOKEN", "")
    if token and urllib.parse.urlsplit(url).netloc in GITHUB_HOSTS:
        headers["Authorization"] = f"token {token}"
    return headers


def _http_failure(url: str, exc: urllib.error.HTTPError) -> UpstreamError:
    """Classify an HTTP error. Only a real quota signal is fatal.

    A forge answering 403 is usually refusing the request, not reporting a
    quota: small Forgejo instances behind anti-bot filters do it routinely.
    GitHub reports exhaustion with X-RateLimit-Remaining: 0, and 429 is the
    standard quota status everywhere, so those two are the only fatal cases.
    """
    if exc.code == 429:
        return RateLimitError(f"{url}: HTTP 429")
    if exc.code == 403 and exc.headers is not None:
        remaining = exc.headers.get("X-RateLimit-Remaining")
        if remaining is not None and remaining.strip() == "0":
            return RateLimitError(f"{url}: HTTP 403, quota exhausted")
    return UpstreamError(f"{url}: HTTP {exc.code}")


def _fetch(url: str, accept_json: bool = False) -> bytes | None:
    """Body of a GET, or None on 404.

    A pass over every profile issues thousands of requests, so a dropped
    connection or a transient 5xx is a certainty rather than an accident.
    Those are retried; a definitive answer from the forge is not.
    """
    failure: UpstreamError | None = None
    for attempt in range(RETRIES):
        req = urllib.request.Request(url, headers=_headers(url, accept_json))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            failure = _http_failure(url, exc)
            if isinstance(failure, RateLimitError) or exc.code < 500:
                raise failure from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            failure = UpstreamError(f"{url}: {exc}")
        if attempt + 1 < RETRIES:
            _sleep(RETRY_BACKOFF[attempt])
    raise failure


def _http_text(url: str) -> str | None:
    """Text body of a GET, or None on 404. Replaced in tests."""
    body = _fetch(url)
    return None if body is None else body.decode("utf-8", errors="replace")


def _http_json(url: str) -> object | None:
    """Parsed JSON body of a GET, or None on 404. Replaced in tests."""
    body = _fetch(url, accept_json=True)
    return None if body is None else json.loads(body.decode())


def cache_path(cache_dir: str, repo: Repo, sha: str, path: str) -> Path:
    """Content-addressed location for one path at one revision."""
    root = Path(cache_dir) / repo.host / repo.owner / repo.name / sha
    safe = path.replace("\\", "/").strip("/")
    target = (root / safe).resolve()
    base = root.resolve()
    if not str(target).startswith(str(base) + os.sep) and target != base:
        target = base / safe.replace("/", "_").replace("..", "_")
    return target


def write_cache(target: Path, text: str) -> None:
    """Atomic write: unique scratch in the target directory, then replace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, scratch = tempfile.mkstemp(dir=str(target.parent), suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(scratch, target)
    except OSError:
        Path(scratch).unlink(missing_ok=True)
        raise


def fetch_file(
    repo: Repo,
    sha: str,
    path: str,
    cache_dir: str,
    offline: bool = False,
) -> list[str] | None:
    """Lines of one path at one revision, or None when absent."""
    target = cache_path(cache_dir, repo, sha, path)
    if target.is_file():
        text = target.read_text(encoding="utf-8")
        return None if text == ABSENT else text.splitlines()
    if offline:
        return None
    text = _http_text(raw_url(repo, sha, path))
    write_cache(target, ABSENT if text is None else text)
    return None if text is None else text.splitlines()


def _api(url: str, cache_dir: str, offline: bool) -> object | None:
    """Cached API call. The cache stores absence as well as payloads."""
    key = hashlib.sha256(url.encode()).hexdigest()
    target = Path(cache_dir) / "_api" / f"{key}.json"
    if target.is_file():
        raw = target.read_text(encoding="utf-8")
        return None if raw == ABSENT else json.loads(raw)
    if offline:
        return None
    payload = _http_json(url)
    write_cache(target, ABSENT if payload is None else json.dumps(payload))
    return payload


def _project(repo: Repo) -> str:
    return urllib.parse.quote(f"{repo.owner}/{repo.name}", safe="")


def _commits_url(repo: Repo, date: str | None, branch: str | None = None) -> str:
    if repo.family == "github":
        base = f"{repo.api_base}/repos/{repo.slug}/commits?per_page=1"
        if branch:
            base += f"&sha={urllib.parse.quote(branch, safe='')}"
    elif repo.family == "gitlab":
        base = (
            f"{repo.api_base}/projects/{_project(repo)}"
            f"/repository/commits?per_page=1"
        )
        if branch:
            base += f"&ref_name={urllib.parse.quote(branch, safe='')}"
    else:
        base = f"{repo.api_base}/repos/{repo.slug}/commits?limit=1"
        if branch:
            base += f"&sha={urllib.parse.quote(branch, safe='')}"
    return f"{base}&until={date}T23:59:59Z" if date else base


def _first_sha(payload: object) -> str | None:
    if isinstance(payload, list) and payload:
        head = payload[0]
        if isinstance(head, dict):
            return head.get("sha") or head.get("id")
    return None


def resolve_head(
    repo: Repo, cache_dir: str, offline: bool = False, branch: str | None = None
) -> str | None:
    """Sha of a branch tip, the default branch unless one is named.

    A libretro port often lives on a branch of a fork rather than on the
    default branch, so the code a profile documents can be absent from the
    tip the forge serves by default.
    """
    return _first_sha(_api(_commits_url(repo, None, branch), cache_dir, offline))


def resolve_commit_at(
    repo: Repo, date: str, cache_dir: str, offline: bool = False,
    branch: str | None = None,
) -> str | None:
    """Last commit on or before a date, on the default branch or a named one."""
    return _first_sha(_api(_commits_url(repo, date, branch), cache_dir, offline))


def _tags_url(repo: Repo) -> str:
    if repo.family == "gitlab":
        return (
            f"{repo.api_base}/projects/{_project(repo)}"
            f"/repository/tags?per_page=100"
        )
    return f"{repo.api_base}/repos/{repo.slug}/tags?per_page=100"


def list_tags(repo: Repo, cache_dir: str, offline: bool = False) -> list[str]:
    """Tag names, newest first as the forge orders them."""
    payload = _api(_tags_url(repo), cache_dir, offline)
    if not isinstance(payload, list):
        return []
    return [t["name"] for t in payload if isinstance(t, dict) and t.get("name")]


def resolve_tag_commit(
    repo: Repo, tag: str, cache_dir: str, offline: bool = False
) -> str | None:
    """Commit a tag points at."""
    payload = _api(_tags_url(repo), cache_dir, offline)
    if not isinstance(payload, list):
        return None
    for entry in payload:
        if not isinstance(entry, dict) or entry.get("name") != tag:
            continue
        commit = entry.get("commit")
        if isinstance(commit, dict):
            return commit.get("sha") or commit.get("id")
    return None


def tag_commit(
    repo: Repo, tag: str, cache_dir: str, offline: bool = False
) -> str | None:
    """Commit a named tag points at, looked up directly.

    Listing tags is paginated, and a repository publishing nightly tags pushes
    an old release far past the first page, so the tag is asked for by name.
    An annotated tag points at a tag object, which is dereferenced.
    """
    if repo.family != "github":
        return resolve_tag_commit(repo, tag, cache_dir, offline)
    quoted = urllib.parse.quote(tag)
    payload = _api(
        f"{repo.api_base}/repos/{repo.slug}/git/ref/tags/{quoted}",
        cache_dir,
        offline,
    )
    if not isinstance(payload, dict):
        return None
    obj = payload.get("object")
    if not isinstance(obj, dict):
        return None
    if obj.get("type") != "tag":
        return obj.get("sha")
    annotated = _api(
        f"{repo.api_base}/repos/{repo.slug}/git/tags/{obj.get('sha')}",
        cache_dir,
        offline,
    )
    target = annotated.get("object") if isinstance(annotated, dict) else None
    return target.get("sha") if isinstance(target, dict) else None


def _releases_url(repo: Repo) -> str:
    if repo.family == "gitlab":
        return f"{repo.api_base}/projects/{_project(repo)}/releases"
    return f"{repo.api_base}/repos/{repo.slug}/releases/latest"


def latest_release(
    repo: Repo, cache_dir: str, offline: bool = False
) -> Release | None:
    """Most recent release the forge exposes."""
    payload = _api(_releases_url(repo), cache_dir, offline)
    if isinstance(payload, list):
        payload = payload[0] if payload else None
    if not isinstance(payload, dict):
        return None
    tag = payload.get("tag_name") or payload.get("tag") or ""
    stamp = payload.get("published_at") or payload.get("released_at") or ""
    if not tag:
        return None
    return Release(str(tag), str(stamp)[:10], bool(payload.get("prerelease")))


def _compare_url(repo: Repo, base: str, head: str) -> str:
    if repo.family == "gitlab":
        return (
            f"{repo.api_base}/projects/{_project(repo)}"
            f"/repository/compare?from={base}&to={head}"
        )
    return f"{repo.api_base}/repos/{repo.slug}/compare/{base}...{head}"


def _changes_from_github(payload: dict) -> list[FileChange]:
    return [
        FileChange(
            entry.get("status", "modified"),
            entry.get("filename", ""),
            entry.get("previous_filename"),
        )
        for entry in (payload.get("files") or [])
        if isinstance(entry, dict)
    ]


def _changes_from_gitlab(payload: dict) -> list[FileChange]:
    changes = []
    for entry in payload.get("diffs") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("renamed_file"):
            status = "renamed"
        elif entry.get("new_file"):
            status = "added"
        elif entry.get("deleted_file"):
            status = "removed"
        else:
            status = "modified"
        previous = entry.get("old_path") if status == "renamed" else None
        changes.append(FileChange(status, entry.get("new_path", ""), previous))
    return changes


def compare(
    repo: Repo, base: str, head: str, cache_dir: str, offline: bool = False
) -> CompareResult:
    """Tree difference between two revisions."""
    payload = _api(_compare_url(repo, base, head), cache_dir, offline)
    if not isinstance(payload, dict):
        return CompareResult([], True)
    if repo.family == "gitlab":
        files = _changes_from_gitlab(payload)
    else:
        files = _changes_from_github(payload)
    truncated = bool(payload.get("truncated")) or len(files) >= GITHUB_COMPARE_CAP
    return CompareResult(files, truncated)


def find_renamed(result: CompareResult, path: str) -> str | None:
    """New path of a file the comparison reports as renamed."""
    for change in result.files:
        if change.status == "renamed" and change.previous_path == path:
            return change.path
    return None


def _tree_url(repo: Repo, sha: str) -> str | None:
    if repo.family == "gitlab":
        return None
    return f"{repo.api_base}/repos/{repo.slug}/git/trees/{sha}?recursive=1"


def list_tree(
    repo: Repo, sha: str, cache_dir: str, offline: bool = False
) -> tuple[list[str], bool]:
    """Every blob path at one revision, and whether the forge truncated it."""
    url = _tree_url(repo, sha)
    if url is None:
        return [], True
    payload = _api(url, cache_dir, offline)
    if not isinstance(payload, dict):
        return [], True
    paths = [
        entry["path"]
        for entry in payload.get("tree") or []
        if isinstance(entry, dict) and entry.get("type") == "blob" and entry.get("path")
    ]
    return paths, bool(payload.get("truncated"))


def commits_touching(
    repo: Repo, path: str, base: str, cache_dir: str, offline: bool = False
) -> int:
    """Commits touching one path since a revision."""
    quoted = urllib.parse.quote(path)
    if repo.family == "gitlab":
        url = (
            f"{repo.api_base}/projects/{_project(repo)}"
            f"/repository/commits?path={quoted}&per_page=100"
        )
    elif repo.family == "github":
        url = (
            f"{repo.api_base}/repos/{repo.slug}/commits"
            f"?path={quoted}&sha={base}&per_page=100"
        )
    else:
        url = f"{repo.api_base}/repos/{repo.slug}/commits?path={quoted}&limit=100"
    payload = _api(url, cache_dir, offline)
    return len(payload) if isinstance(payload, list) else 0
