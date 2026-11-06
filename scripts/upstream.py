"""Access to upstream source repositories.

Resolves revisions, fetches files by sha, and compares trees across the
forge families the emulator profiles point at. Knows nothing about profile
structure.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from artifacts import set_plain_mode

USER_AGENT = "retrobios-profile-sync/1.0"
# Where fetched upstream files live, shared by every reader of this cache.
CACHE_DIR = ".cache/upstream"
ABSENT = "\0absent\0"
GITHUB_COMPARE_CAP = 300
RETRIES = 3
RETRY_BACKOFF = (0.5, 2.0)
# A 429 is waited out, as base_scraper does: git.libretro.com answers it
# a few hundred requests into a pass and serves again a minute later.
RATE_LIMIT_WAITS = (5.0, 20.0, 60.0)
RATE_LIMIT_WAIT_CAP = 120.0
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
    # libretro builds a growing share of its cores from its own GitLab, and
    # several ports (wqxemu, cemu-libretro, libretro-radio) live only there.
    "git.libretro.com": (
        "gitlab",
        "https://git.libretro.com/api/v4",
        "https://git.libretro.com",
    ),
    # EDuke32 and its forks (eduke32, fury) are developed on this GitLab.
    "voidpoint.io": (
        "gitlab",
        "https://voidpoint.io/api/v4",
        "https://voidpoint.io",
    ),
    "codeberg.org": (
        "forgejo",
        "https://codeberg.org/api/v1",
        "https://codeberg.org",
    ),
    # The Ryujinx repository left GitHub in October 2024. This Gitea pull
    # mirror kept its history up to 1.1.1402.
    "git.ngram.ca": (
        "forgejo",
        "https://git.ngram.ca/api/v1",
        "https://git.ngram.ca",
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
    "git.ryujinx.app": (
        "forgejo",
        "https://git.ryujinx.app/api/v1",
        "https://git.ryujinx.app",
    ),
}


_sleep = time.sleep
# Hosts still refusing after every wait. Asking them again in the same pass
# only spends the waits again, while the other forges keep answering.
_exhausted_hosts: set[str] = set()


class UpstreamError(Exception):
    """Any failure while talking to a forge."""


class RateLimitError(UpstreamError):
    """The forge refused the request for quota reasons."""

    def __init__(self, message: str, host: str = "") -> None:
        super().__init__(message)
        self.host = host


class NotCachedError(UpstreamError):
    """An offline read of something the cache never stored.

    Distinct from absence: returning None made profile_sync report a file
    that exists as GONE, "absent at HEAD, no rename found".
    """


class GoneError(UpstreamError):
    """The upstream is not coming back.

    A legal takedown, a resource the forge reports as gone, or a host that
    no longer resolves. Retrying costs time and ends in the same place, and
    a caller sweeping every profile wants this told apart from a forge
    having a bad minute: one is a fact about the project, the other is
    weather.
    """


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
    # The forge reports the two revisions on separate lines of history: the
    # base is no ancestor of the head. A pin in that state survives only
    # while the forge keeps the orphaned object (advancemame, 2026-10-05).
    diverged: bool = False


def parse_repo(url: str) -> Repo | None:
    """Build a Repo from a forge URL, or None when the host is unknown."""
    if not url:
        return None
    parts = urllib.parse.urlsplit(url.strip())
    entry = _HOSTS.get(parts.netloc)
    if entry is None:
        return None
    segments = [s for s in parts.path.split("/") if s]
    family, api_base, raw_base = entry
    if family == "gitlab" and "-" in segments:
        # GitLab nests projects in subgroups; "/-/" opens the project's pages.
        segments = segments[: segments.index("-")]
    if len(segments) < 2:
        return None
    if family == "gitlab":
        owner, name = "/".join(segments[:-1]), segments[-1]
    else:
        owner, name = segments[0], segments[1]
    if name.endswith(".git"):
        name = name[:-4]
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


def content_url(repo: Repo, sha: str, path: str) -> str:
    """URL the tooling fetches one path from.

    Forgejo and Gitea hosts put their web routes, /raw/commit included,
    behind a proof-of-work page (git.ngram.ca answers 200 with an HTML
    challenge), while the API raw route is not challenged. raw_url stays the
    link a reader opens.
    """
    if repo.family != "forgejo":
        return raw_url(repo, sha, path)
    quoted = urllib.parse.quote(path)
    return f"{repo.api_base}/repos/{repo.owner}/{repo.name}/raw/{quoted}?ref={sha}"


def _headers(url: str, accept_json: bool = False) -> dict[str, str]:
    """Request headers. GITHUB_TOKEN is only ever sent to GitHub."""
    headers = {"User-Agent": USER_AGENT}
    if accept_json:
        headers["Accept"] = "application/json"
    if urllib.parse.urlsplit(url).netloc in GITHUB_HOSTS:
        from common import github_token  # noqa: PLC0415

        # GITHUB_TOKEN, else the one gh is logged in with.
        token = github_token()
        if token:
            headers["Authorization"] = f"token {token}"
    return headers


def _http_failure(url: str, exc: urllib.error.HTTPError) -> UpstreamError:
    """Classify an HTTP error. Only a real quota signal is fatal.

    A forge answering 403 is usually refusing the request, not reporting a
    quota: small Forgejo instances behind anti-bot filters do it routinely.
    GitHub reports exhaustion with X-RateLimit-Remaining: 0, and 429 is the
    standard quota status everywhere, so those two are the only fatal cases.
    """
    host = urllib.parse.urlsplit(url).hostname or ""
    if exc.code == 429:
        retry_after = (exc.headers.get("Retry-After") or "").strip() if exc.headers else ""
        wait = f", retry after {retry_after} s" if retry_after.isdigit() else ""
        return RateLimitError(f"{url}: HTTP 429{wait}", host)
    if exc.code in (410, 451):
        reason = "withdrawn for legal reasons" if exc.code == 451 else "gone"
        return GoneError(f"{url}: HTTP {exc.code}, {reason}")
    if exc.code == 403 and exc.headers is not None:
        remaining = exc.headers.get("X-RateLimit-Remaining")
        if remaining is not None and remaining.strip() == "0":
            return RateLimitError(f"{url}: HTTP 403, quota exhausted", host)
    return UpstreamError(f"{url}: HTTP {exc.code}")


def _host_is_unresolvable(exc: BaseException) -> bool:
    """Whether a connection failure is the name itself, not the network.

    URLError carries the cause in `reason`, and a wrapped one carries it in
    `__cause__`. The walk is bounded because either chain can be cyclic.
    """
    seen: BaseException | None = exc
    for _ in range(8):
        if seen is None:
            break
        if isinstance(seen, socket.gaierror):
            # A resolver that answers nothing at all is the local network:
            # every profile would read as gone, and the sweep would report
            # nothing to review while it reviewed nothing.
            return seen.errno == socket.EAI_NONAME and _resolver_answers()
        nested = getattr(seen, "reason", None)
        seen = nested if isinstance(nested, BaseException) else seen.__cause__
    return False


# A name every forge call depends on: if it does not resolve, the fault is
# local and no host can be declared gone.
RESOLVER_PROBE = "github.com"


def _resolver_answers() -> bool:
    """Whether name resolution works here at all. Replaced in tests."""
    try:
        socket.getaddrinfo(RESOLVER_PROBE, 443)
    except OSError:
        return False
    return True


def _rate_limit_wait(exc: urllib.error.HTTPError, waited: int) -> float | None:
    """Seconds to wait before asking again, or None when waiting is futile.

    GitHub's exhausted quota (403) resets on the hour. A 429 names its wait
    in Retry-After, which is followed up to a cap, else the fixed steps.
    """
    if exc.code != 429 or waited >= len(RATE_LIMIT_WAITS):
        return None
    retry_after = (exc.headers.get("Retry-After") or "").strip() if exc.headers else ""
    if retry_after.isdigit():
        delay = float(retry_after)
        return delay if delay <= RATE_LIMIT_WAIT_CAP else None
    return RATE_LIMIT_WAITS[waited]


def _fetch(url: str, accept_json: bool = False) -> bytes | None:
    """Body of a GET, or None on 404.

    A pass over every profile issues thousands of requests, so a dropped
    connection or a transient 5xx is a certainty rather than an accident.
    Those are retried, a definitive answer from the forge is not. A rate
    limit is waited out, and a host that outlasts the waits is not asked
    again in this process.
    """
    host = urllib.parse.urlsplit(url).hostname or ""
    if host in _exhausted_hosts:
        raise RateLimitError(f"{url}: {host} rate limited earlier in this run", host)
    failure: UpstreamError | None = None
    attempt = 0
    waited = 0
    while True:
        req = urllib.request.Request(url, headers=_headers(url, accept_json))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            failure = _http_failure(url, exc)
            if isinstance(failure, RateLimitError):
                delay = _rate_limit_wait(exc, waited)
                if delay is None:
                    _exhausted_hosts.add(host)
                    raise failure from exc
                waited += 1
                _sleep(delay)
                continue
            if exc.code < 500:
                raise failure from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            if _host_is_unresolvable(exc):
                raise GoneError(f"{url}: host does not resolve") from exc
            failure = UpstreamError(f"{url}: {exc}")
        attempt += 1
        if attempt >= RETRIES:
            raise failure
        _sleep(RETRY_BACKOFF[attempt - 1])


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
    """Atomic write: unique scratch in the target directory, then replace.

    A profile can cite both a directory and files inside it, and the first
    citation caches `vice/data/C64DTV` as a file, which then blocks the
    directory the second one needs. The cache is derived data, so a collision
    skips the write rather than failing the read.
    """
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except (FileExistsError, NotADirectoryError):
        return
    fd, scratch = tempfile.mkstemp(dir=str(target.parent), suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        set_plain_mode(scratch)
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
    """Lines of one path at one revision, or None when absent.

    Offline, a path the cache never stored raises NotCachedError: nothing
    is known about it, which is not the same as knowing it is absent.
    """
    target = cache_path(cache_dir, repo, sha, path)
    if target.is_file():
        text = target.read_text(encoding="utf-8")
        return None if text == ABSENT else text.splitlines()
    if offline:
        raise NotCachedError(f"{repo.slug}@{sha[:8]}:{path} is not in the offline cache")
    text = _http_text(content_url(repo, sha, path))
    write_cache(target, ABSENT if text is None else text)
    return None if text is None else text.splitlines()


# How long an answer about a moving reference stays trusted. A branch tip, a
# tag list or a release list changes under the profile: libretro/hatari grew
# a new main branch after its tip was first cached, and every comparison
# then ran against the old branch. Content addressed by a sha or a date
# never changes and is cached for good.
MOVING_TTL = 6 * 3600


def _api_target(url: str, cache_dir: str) -> Path:
    """Where the cached answer to one API call lives."""
    key = hashlib.sha256(url.encode()).hexdigest()
    return Path(cache_dir) / "_api" / f"{key}.json"


def _require_cached(url: str, cache_dir: str, offline: bool, what: str) -> None:
    """Offline, refuse a call the cache holds no answer to, absence included.

    _api answers None both for a resource the forge does not have and for
    one never asked, and only the first is a fact.
    """
    if offline and not _api_target(url, cache_dir).is_file():
        raise NotCachedError(f"{what} is not in the offline cache")


def _api(
    url: str, cache_dir: str, offline: bool, max_age: float | None = None,
    absent_max_age: float | None = None,
) -> object | None:
    """Cached API call. The cache stores absence as well as payloads.

    ``max_age`` bounds the trust in a cached answer, in seconds. A stale
    answer is refreshed unless the run is offline, when it still serves.
    ``absent_max_age`` bounds a cached absence alone, for a resource that
    can appear but, once there, does not change.
    """
    target = _api_target(url, cache_dir)
    if target.is_file():
        raw = target.read_text(encoding="utf-8")
        bound = (
            absent_max_age
            if raw == ABSENT and absent_max_age is not None
            else max_age
        )
        fresh = bound is None or time.time() - target.stat().st_mtime <= bound
        if fresh or offline:
            return None if raw == ABSENT else json.loads(raw)
    if offline:
        return None
    payload = _http_json(url)
    write_cache(target, ABSENT if payload is None else json.dumps(payload))
    return payload


def fetch_page(url: str, cache_dir: str, offline: bool) -> str | None:
    """A web page's text, cached like a moving API answer (MOVING_TTL).

    A project published outside a forge (Altirra, mednafen, ePSXe) says its
    version on a download page: that page is the only release feed there is.
    """
    key = hashlib.sha256(url.encode()).hexdigest()
    target = Path(cache_dir) / "_pages" / f"{key}.txt"
    if target.is_file():
        fresh = time.time() - target.stat().st_mtime <= MOVING_TTL
        if fresh or offline:
            raw = target.read_text(encoding="utf-8")
            return None if raw == ABSENT else raw
    if offline:
        return None
    text = _http_text(url)
    write_cache(target, ABSENT if text is None else text)
    return text


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


def current_slug(repo: Repo, cache_dir: str, offline: bool = False) -> str | None:
    """The owner/name the forge answers for a repository today.

    A renamed or transferred repository keeps answering under its old name:
    GitHub redirects (AloysHF/NicaiEmu answers as AloysHF/CoolbarEmu), GitLab
    and Gitea do the same. Every later call follows the redirect, so only the
    name in the payload tells the project moved.
    """
    if repo.family == "gitlab":
        url, key = f"{repo.api_base}/projects/{_project(repo)}", "path_with_namespace"
    else:
        url, key = f"{repo.api_base}/repos/{repo.slug}", "full_name"
    payload = _api(url, cache_dir, offline, MOVING_TTL)
    if not isinstance(payload, dict):
        return None
    value = payload.get(key)
    return str(value) if value else None


def resolve_head(
    repo: Repo, cache_dir: str, offline: bool = False, branch: str | None = None,
    fresh: bool = False,
) -> str | None:
    """Sha of a branch tip, the default branch unless one is named.

    A libretro port often lives on a branch of a fork rather than on the
    default branch, so the code a profile documents can be absent from the
    tip the forge serves by default. ``fresh`` asks the forge again whatever
    the cache holds.

    Offline, a tip the cache never stored raises NotCachedError: returning
    None read as a branch the forge does not have, and profile_sync dropped
    xenios-jp/XeniOS, judging its citations against the other repository.
    """
    url = _commits_url(repo, None, branch)
    _require_cached(
        url, cache_dir, offline, f"{repo.slug}: tip of {branch or 'the default branch'}"
    )
    return _first_sha(_api(url, cache_dir, offline, 0 if fresh else MOVING_TTL))


def resolve_commit_at(
    repo: Repo, date: str, cache_dir: str, offline: bool = False,
    branch: str | None = None,
) -> str | None:
    """Last commit on or before a date, on the default branch or a named one.

    Offline, an answer the cache never stored raises NotCachedError, as a
    branch tip does: None means the forge has no such commit.
    """
    if repo.family in ("github", "gitlab"):
        url = _commits_url(repo, date, branch)
        _require_cached(url, cache_dir, offline, f"{repo.slug}: commit at {date}")
        return _first_sha(_api(url, cache_dir, offline))
    return _gitea_commit_at(repo, date, cache_dir, offline, branch)


# Gitea and Forgejo serve 50 commits a page at most.
GITEA_PAGE = 50


def _gitea_commit_at(
    repo: Repo, date: str, cache_dir: str, offline: bool,
    branch: str | None,
) -> str | None:
    """Walk the history newest first to the first commit dated by the cutoff.

    The Gitea and Forgejo commits API ignores ``until`` and answers with the
    tip: gam4980's profiled_date of 2026-03-23 resolved to a commit of July,
    a revision the profile never read.
    """
    cutoff = datetime.fromisoformat(f"{date}T23:59:59+00:00")
    base = (
        f"{repo.api_base}/repos/{repo.slug}/commits?limit={GITEA_PAGE}"
        "&stat=false&verification=false&files=false"
    )
    if branch:
        base += f"&sha={urllib.parse.quote(branch, safe='')}"
    page = 1
    while True:
        url = f"{base}&page={page}"
        _require_cached(url, cache_dir, offline, f"{repo.slug}: commit at {date}")
        payload = _api(url, cache_dir, offline, MOVING_TTL)
        if not isinstance(payload, list) or not payload:
            return None
        for entry in payload:
            stamp = _gitea_commit_date(entry)
            if stamp is not None and stamp <= cutoff:
                return entry.get("sha")
        page += 1


def _gitea_commit_date(entry: object) -> datetime | None:
    if not isinstance(entry, dict):
        return None
    commit = entry.get("commit")
    committer = commit.get("committer") if isinstance(commit, dict) else None
    raw = committer.get("date") if isinstance(committer, dict) else None
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _tags_url(repo: Repo) -> str:
    if repo.family == "gitlab":
        return (
            f"{repo.api_base}/projects/{_project(repo)}"
            f"/repository/tags?per_page=100"
        )
    return f"{repo.api_base}/repos/{repo.slug}/tags?per_page=100"


def list_tags(repo: Repo, cache_dir: str, offline: bool = False) -> list[str]:
    """Tag names, newest first as the forge orders them."""
    payload = _api(_tags_url(repo), cache_dir, offline, MOVING_TTL)
    if not isinstance(payload, list):
        return []
    return [t["name"] for t in payload if isinstance(t, dict) and t.get("name")]


GITHUB_GRAPHQL = "https://api.github.com/graphql"
_NEWEST_TAG_QUERY = (
    "query($owner:String!,$name:String!){repository(owner:$owner,name:$name)"
    "{refs(refPrefix:\"refs/tags/\",first:1,"
    "orderBy:{field:TAG_COMMIT_DATE,direction:DESC}){nodes{name}}}}"
)


def _github_graphql(
    query: str, variables: dict, cache_dir: str, offline: bool
) -> object | None:
    """A cached GitHub GraphQL answer, or None without a token.

    GraphQL refuses anonymous calls, so an untokened run keeps the REST
    answer it already had.
    """
    from common import github_token  # noqa: PLC0415

    body = json.dumps({"query": query, "variables": variables}, sort_keys=True)
    target = Path(cache_dir) / "_api" / f"{hashlib.sha256(body.encode()).hexdigest()}.json"
    if target.is_file():
        fresh = time.time() - target.stat().st_mtime <= MOVING_TTL
        if fresh or offline:
            return json.loads(target.read_text(encoding="utf-8"))
    token = github_token()
    if offline or not token:
        return None
    headers = _headers(GITHUB_GRAPHQL, accept_json=True)
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        GITHUB_GRAPHQL, data=body.encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise _http_failure(GITHUB_GRAPHQL, exc) from exc
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        raise UpstreamError(f"{GITHUB_GRAPHQL}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("errors"):
        return None
    write_cache(target, json.dumps(payload))
    return payload


def newest_tag(repo: Repo, cache_dir: str, offline: bool = False) -> str | None:
    """The tag on the newest commit.

    GitHub's REST listing sorts tags by name: nesoid lists 2.5 before 2.5-4,
    gargoyle stable-20090825 before 2026.1.1. GraphQL sorts by commit date.
    Elsewhere, or without a token, the forge's own first entry.
    """
    if repo.family == "github":
        payload = _github_graphql(
            _NEWEST_TAG_QUERY, {"owner": repo.owner, "name": repo.name},
            cache_dir, offline,
        )
        try:
            nodes = payload["data"]["repository"]["refs"]["nodes"]
        except (TypeError, KeyError):
            nodes = None
        if isinstance(nodes, list):
            return nodes[0].get("name") if nodes else None
    tags = list_tags(repo, cache_dir, offline)
    return tags[0] if tags else None


def resolve_tag_commit(
    repo: Repo, tag: str, cache_dir: str, offline: bool = False
) -> str | None:
    """Commit a tag points at."""
    payload = _api(_tags_url(repo), cache_dir, offline, MOVING_TTL)
    if not isinstance(payload, list):
        return None
    for entry in payload:
        if not isinstance(entry, dict) or entry.get("name") != tag:
            continue
        commit = entry.get("commit")
        if isinstance(commit, dict):
            return commit.get("sha") or commit.get("id")
    return None


def _named_tag_commit(
    repo: Repo, tag: str, cache_dir: str, offline: bool
) -> str | None:
    """A GitLab or Forgejo tag's commit, asked for by name."""
    quoted = urllib.parse.quote(tag, safe="")
    if repo.family == "gitlab":
        url = f"{repo.api_base}/projects/{_project(repo)}/repository/tags/{quoted}"
    else:
        url = f"{repo.api_base}/repos/{repo.slug}/tags/{quoted}"
    payload = _api(url, cache_dir, offline, absent_max_age=MOVING_TTL)
    commit = payload.get("commit") if isinstance(payload, dict) else None
    if not isinstance(commit, dict):
        return None
    return commit.get("id") or commit.get("sha")


def tag_commit(
    repo: Repo, tag: str, cache_dir: str, offline: bool = False
) -> str | None:
    """Commit a named tag points at, looked up directly.

    Listing tags is paginated, and a repository publishing nightly tags pushes
    an old release far past the first page, so the tag is asked for by name.
    An annotated tag points at a tag object, which is dereferenced.
    """
    if repo.family != "github":
        return _named_tag_commit(repo, tag, cache_dir, offline) or resolve_tag_commit(
            repo, tag, cache_dir, offline
        )
    quoted = urllib.parse.quote(tag)
    # A tag pushed after the first lookup must be seen: the 404 expires,
    # the commit a tag names does not.
    payload = _api(
        f"{repo.api_base}/repos/{repo.slug}/git/ref/tags/{quoted}",
        cache_dir,
        offline,
        absent_max_age=MOVING_TTL,
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
    payload = _api(_releases_url(repo), cache_dir, offline, MOVING_TTL)
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
    return CompareResult(files, truncated, payload.get("status") == "diverged")


def _commits_ahead(payload: object, family: str) -> int | None:
    """Commits the compare head carries that its base does not."""
    if not isinstance(payload, dict):
        return None
    if family == "github":
        value = payload.get("ahead_by")
    elif family == "gitlab":
        value = len(payload.get("commits") or [])
    else:
        value = payload.get("total_commits")
    return value if isinstance(value, int) else None


def fork_base(
    repo: Repo, sha: str, fork: Repo, fork_sha: str, cache_dir: str,
    offline: bool = False,
) -> str | None:
    """The commit of ``repo`` that ``fork`` at ``fork_sha`` has merged up to.

    GitHub compares across a fork network and names the merge base. Two
    repositories outside one network answer 404, and None is returned.
    """
    if repo.family != "github" or fork.family != "github":
        return None
    payload = _api(
        f"{repo.api_base}/repos/{repo.slug}/compare/"
        f"{sha}...{fork.owner}:{fork.name}:{fork_sha}",
        cache_dir, offline,
    )
    base = payload.get("merge_base_commit") if isinstance(payload, dict) else None
    return base.get("sha") if isinstance(base, dict) else None


def ancestry(
    repo: Repo, base: str, head: str, cache_dir: str, offline: bool = False
) -> tuple[int, int] | None:
    """(ahead, behind): commits head has that base lacks, and the reverse.

    Two shas never change their history, so both answers are cached for
    good. GitHub gives both counts in one answer, GitLab and Forgejo list
    one direction only and are asked twice.
    """
    forward = _api(_compare_url(repo, base, head), cache_dir, offline)
    ahead = _commits_ahead(forward, repo.family)
    if ahead is None:
        return None
    if repo.family == "github":
        behind = forward.get("behind_by")
    else:
        behind = _commits_ahead(
            _api(_compare_url(repo, head, base), cache_dir, offline), repo.family
        )
    return (ahead, behind) if isinstance(behind, int) else None


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


def list_directory(
    repo: Repo, sha: str, path: str, cache_dir: str, offline: bool = False
) -> list[str] | None:
    """Names of the blobs directly under one directory at one revision.

    One request for the directory alone, where the whole tree of a large
    repository comes back truncated. None when the forge has no such call
    or the directory does not exist there.
    """
    if repo.family != "github":
        return None
    url = f"{repo.api_base}/repos/{repo.slug}/git/trees/{sha}:{path.strip('/')}"
    payload = _api(url, cache_dir, offline)
    if not isinstance(payload, dict) or payload.get("truncated"):
        return None
    return sorted(
        entry["path"]
        for entry in payload.get("tree") or []
        if isinstance(entry, dict) and entry.get("type") == "blob" and entry.get("path")
    )


TREE_PAGE_SIZE = 100
MAX_TREE_PAGES = 50


def _gitlab_tree(
    repo: Repo, sha: str, cache_dir: str, offline: bool
) -> tuple[list[str], bool]:
    """GitLab serves its tree in pages, each page cached on its own URL.

    A page that cannot be read mid-walk reports the listing as truncated:
    the paths already collected are real, but their absence proves nothing.
    """
    paths: list[str] = []
    for page in range(1, MAX_TREE_PAGES + 1):
        url = (
            f"{repo.api_base}/projects/{_project(repo)}/repository/tree"
            f"?ref={sha}&recursive=true&per_page={TREE_PAGE_SIZE}&page={page}"
        )
        payload = _api(url, cache_dir, offline)
        if not isinstance(payload, list):
            return paths, True
        paths.extend(
            entry["path"]
            for entry in payload
            if isinstance(entry, dict)
            and entry.get("type") == "blob"
            and entry.get("path")
        )
        if len(payload) < TREE_PAGE_SIZE:
            return paths, False
    return paths, True


def cache_gitlab_directory(
    repo: Repo, sha: str, directory: str, cache_dir: str, offline: bool = False
) -> set[str] | None:
    """Every file under one GitLab directory, cached from one request.

    GitLab counts anonymous requests per IP: reading Recalbox's hundred
    system.ini files one raw URL at a time ran into HTTP 429 before the
    end. The archive endpoint serves the directory in one request, and when
    the API itself is refused, a shallow sparse git fetch does, since GitLab
    does not count git traffic against that quota. Each file goes to the
    cache `fetch_file` reads, and the list of paths is kept so a later run,
    offline included, knows what is absent. None when the list is not
    known (offline, never fetched).
    """
    directory = directory.strip("/")
    index = cache_path(cache_dir, repo, sha, f".archives/{directory}.json")
    if index.is_file():
        return set(json.loads(index.read_text(encoding="utf-8")))
    if offline or repo.family != "gitlab":
        return None
    try:
        files = _gitlab_archive_files(repo, sha, directory)
    except RateLimitError:
        files = _sparse_git_files(repo, sha, directory, cache_dir)
    if not files:
        raise UpstreamError(f"{repo.slug}@{sha[:8]}: nothing under {directory}")
    for path, text in files.items():
        write_cache(cache_path(cache_dir, repo, sha, path), text)
    write_cache(index, json.dumps(sorted(files)))
    return set(files)


def _gitlab_archive_files(repo: Repo, sha: str, directory: str) -> dict[str, str]:
    url = (
        f"{repo.api_base}/projects/{_project(repo)}/repository/archive.tar.gz"
        f"?sha={sha}&path={urllib.parse.quote(directory)}"
    )
    body = _fetch(url)
    if body is None:
        return {}
    prefix = directory + "/"
    files: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            # The archive wraps everything in one <project>-<sha>-<path> folder.
            inner = member.name.split("/", 1)[-1]
            handle = archive.extractfile(member) if inner.startswith(prefix) else None
            if handle is not None:
                files[inner] = handle.read().decode("utf-8", errors="replace")
    return files


def _sparse_git_files(repo: Repo, sha: str, directory: str, cache_dir: str) -> dict[str, str]:
    """One directory at one commit through git: depth 1, blobs of that
    directory only, in a scratch work tree removed afterwards."""
    url = f"https://{repo.host}/{repo.slug}.git"
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(dir=cache_dir, prefix=".sparse-"))
    try:
        steps = (
            ["init", "--quiet"],
            ["remote", "add", "origin", url],
            ["sparse-checkout", "set", "--no-cone", f"/{directory}/"],
            ["fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", sha],
            ["checkout", "--quiet", "FETCH_HEAD"],
        )
        for argv in steps:
            result = _git(argv, work)
            if result.returncode:
                raise UpstreamError(f"{url}: git {argv[0]} failed: {result.stderr.strip()}")
        root = work / directory
        return {
            f"{directory}/{p.relative_to(root).as_posix()}": p.read_text(encoding="utf-8", errors="replace")
            for p in sorted(root.rglob("*")) if p.is_file()
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def list_tree(
    repo: Repo, sha: str, cache_dir: str, offline: bool = False
) -> tuple[list[str], bool]:
    """Every blob path at one revision, and whether the forge truncated it."""
    if repo.family == "gitlab":
        return _gitlab_tree(repo, sha, cache_dir, offline)
    url = _tree_url(repo, sha)
    if url is None:
        return [], True
    payload = _api(url, cache_dir, offline)
    if not isinstance(payload, dict):
        return [], True
    entries = list(payload.get("tree") or [])
    truncated = bool(payload.get("truncated"))
    # Forgejo pages a recursive tree, 1000 entries at a time, and says how
    # many there are: mirrors/Ryujinx holds 4704, and read as one page every
    # citation past the first thousand was unverifiable. GitHub reports no
    # count, its truncation is final.
    total = payload.get("total_count")
    if truncated and repo.family == "forgejo" and isinstance(total, int):
        for page in range(2, MAX_TREE_PAGES + 1):
            if len(entries) >= total:
                break
            more = _api(f"{url}&page={page}", cache_dir, offline)
            if not isinstance(more, dict) or not more.get("tree"):
                break
            entries.extend(more["tree"])
        truncated = len(entries) < total
    paths = [
        entry["path"]
        for entry in entries
        if isinstance(entry, dict) and entry.get("type") == "blob" and entry.get("path")
    ]
    return paths, truncated


def list_gitlinks(
    repo: Repo, sha: str, cache_dir: str, offline: bool = False
) -> dict[str, str]:
    """Submodule path -> the commit it points at, at one revision.

    Read from the same tree listing as list_tree, so the call costs nothing
    once the tree is cached.
    """
    if repo.family == "gitlab":
        links: dict[str, str] = {}
        for page in range(1, MAX_TREE_PAGES + 1):
            url = (
                f"{repo.api_base}/projects/{_project(repo)}/repository/tree"
                f"?ref={sha}&recursive=true&per_page={TREE_PAGE_SIZE}&page={page}"
            )
            payload = _api(url, cache_dir, offline)
            if not isinstance(payload, list):
                break
            links.update(
                (entry["path"], entry["id"])
                for entry in payload
                if isinstance(entry, dict) and entry.get("type") == "commit"
                and entry.get("path") and entry.get("id")
            )
            if len(payload) < TREE_PAGE_SIZE:
                break
        return links
    url = _tree_url(repo, sha)
    payload = _api(url, cache_dir, offline) if url else None
    if not isinstance(payload, dict):
        return {}
    return {
        entry["path"]: entry["sha"]
        for entry in payload.get("tree") or []
        if isinstance(entry, dict) and entry.get("type") == "commit"
        and entry.get("path") and entry.get("sha")
    }


def submodule_urls(text: str, base: Repo) -> dict[str, Repo]:
    """Submodule path -> repository, read from a .gitmodules text.

    A relative url (`../xash3d-fwgs.git`) names a sibling of the repository
    that declares it, on the same forge.
    """
    repos: dict[str, Repo] = {}
    path = url = None
    for line in [*text.splitlines(), "[end]"]:
        stripped = line.strip()
        if stripped.startswith("["):
            if path and url:
                if url.startswith(("../", "./")):
                    segments = [base.owner, base.name]
                    for part in url.split("/"):
                        if part == "..":
                            segments.pop()
                        elif part not in (".", ""):
                            segments.append(part)
                    url = f"https://{base.host}/{'/'.join(segments)}"
                repo = parse_repo(url)
                if repo is not None:
                    repos[path] = repo
            path = url = None
            continue
        key, _, value = stripped.partition("=")
        if key.strip() == "path":
            path = value.strip()
        elif key.strip() == "url":
            url = value.strip()
    return repos


def through_gitlink(
    repo: Repo, sha: str, path: str, cache_dir: str, offline: bool = False
) -> tuple[Repo, str, str] | None:
    """The submodule repository, commit and inner path a path falls under.

    starship cites `Torch src/Companion.cpp`, a file of the Torch submodule:
    the declared tree holds only the gitlink, which pins the revision.
    """
    links = list_gitlinks(repo, sha, cache_dir, offline)
    link = next((p for p in links if path.startswith(p + "/")), None)
    if link is None:
        return None
    modules = fetch_file(repo, sha, ".gitmodules", cache_dir, offline)
    target = submodule_urls("\n".join(modules or ()), repo).get(link)
    if target is None:
        return None
    return target, links[link], path[len(link) + 1:]


def commit_date(repo: Repo, sha: str, cache_dir: str, offline: bool = False) -> str | None:
    """When a revision was committed, as the forge reports it (ISO 8601)."""
    if repo.family == "gitlab":
        payload = _api(
            f"{repo.api_base}/projects/{_project(repo)}/repository/commits/{sha}",
            cache_dir, offline,
        )
        value = payload.get("committed_date") if isinstance(payload, dict) else None
        return value if isinstance(value, str) else None
    if repo.family == "github":
        url = f"{repo.api_base}/repos/{repo.slug}/commits/{sha}"
    else:
        url = f"{repo.api_base}/repos/{repo.slug}/git/commits/{sha}"
    stamp = _gitea_commit_date(_api(url, cache_dir, offline))
    return stamp.isoformat() if stamp is not None else None


def commits_touching(
    repo: Repo, path: str, base: str, cache_dir: str, offline: bool = False,
    head: str | None = None,
) -> int:
    """Commits touching one path since a revision, on the default branch.

    Listing from the pin counted the history before it: a profile pinned on
    HEAD scored the age of its files as drift. The count is of the commits
    after the pin's date that touch the path, the pin itself excluded.
    """
    if head is not None and head == base:
        return 0
    since = commit_date(repo, base, cache_dir, offline)
    if since is None:
        return 0
    quoted = urllib.parse.quote(path)
    stamp = urllib.parse.quote(since)
    if repo.family == "gitlab":
        url = (
            f"{repo.api_base}/projects/{_project(repo)}"
            f"/repository/commits?path={quoted}&since={stamp}&per_page=100"
        )
    elif repo.family == "github":
        url = (
            f"{repo.api_base}/repos/{repo.slug}/commits"
            f"?path={quoted}&since={stamp}&per_page=100"
        )
    else:
        url = (
            f"{repo.api_base}/repos/{repo.slug}/commits"
            f"?path={quoted}&since={stamp}&limit=100"
        )
    # The list grows with every push touching the path: cached for good, the
    # triage drift score stayed at whatever the first run counted.
    payload = _api(url, cache_dir, offline, MOVING_TTL)
    if not isinstance(payload, list):
        return 0
    return sum(
        1 for entry in payload
        if isinstance(entry, dict) and (entry.get("sha") or entry.get("id")) != base
    )


# Commit graphs kept to count the commits between a tag and a pin. A
# treeless bare clone holds commits and tags only: the files a profile reads
# come from fetch_file, by sha.
GIT_DIR = "_git"


def clone_dir(cache_dir: str, repo: Repo) -> Path:
    """Where the commit graph of a repository is kept."""
    return Path(cache_dir) / GIT_DIR / repo.host / repo.owner / f"{repo.name}.git"


def _git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, env=env, check=False
    )


def _has_commit(clone: Path, sha: str) -> bool:
    return _git(["cat-file", "-e", f"{sha}^{{commit}}"], clone).returncode == 0


def _graph(repo: Repo, sha: str, cache_dir: str, offline: bool) -> Path:
    """A clone holding sha and every tag, fetched again once tags may have moved."""
    clone = clone_dir(cache_dir, repo)
    url = f"https://{repo.host}/{repo.slug}.git"
    if not (clone / "HEAD").is_file():
        if offline:
            raise NotCachedError(f"{repo.slug}: no commit graph in the offline cache")
        clone.parent.mkdir(parents=True, exist_ok=True)
        result = _git(["clone", "--quiet", "--bare", "--filter=tree:0", url, str(clone)])
        if result.returncode:
            raise UpstreamError(f"{url}: clone failed: {result.stderr.strip()}")
        _git(["fetch", "--quiet", "--filter=tree:0", "--tags", "origin"], clone)
    stamp = clone / "FETCH_HEAD"
    fresh = stamp.is_file() and time.time() - stamp.stat().st_mtime <= MOVING_TTL
    if offline or (fresh and _has_commit(clone, sha)):
        if not _has_commit(clone, sha):
            raise NotCachedError(f"{repo.slug}@{sha[:8]}: not in the offline commit graph")
        return clone
    # Tags are fetched again: a tag pushed since the clone can be nearer.
    result = _git(
        ["fetch", "--quiet", "--filter=tree:0", "--force", "--tags", "origin",
         "+refs/heads/*:refs/heads/*"], clone,
    )
    if result.returncode:
        raise UpstreamError(f"{url}: fetch failed: {result.stderr.strip()}")
    if not _has_commit(clone, sha):
        # A commit no branch reaches any more: a rewritten fork, a PR head.
        _git(["fetch", "--quiet", "--filter=tree:0", "origin", sha], clone)
    if not _has_commit(clone, sha):
        raise UpstreamError(f"{url}: {sha[:8]} is on no branch the forge serves")
    return clone


def describe(
    repo: Repo, sha: str, cache_dir: str, offline: bool = False,
    match: str | None = None,
) -> tuple[str, int] | None:
    """The tag nearest to sha in its history, and the commits after it.

    git describe counts the commits sha has that the tag lacks, the count a
    forge compare reports as ahead. ``match`` is a glob the tag must fit.
    None when no tag is reachable from sha.
    """
    clone = _graph(repo, sha, cache_dir, offline)
    argv = ["describe", "--tags", "--long", "--abbrev=40"]
    if match:
        argv += ["--match", match]
    result = _git([*argv, sha], clone)
    if result.returncode:
        if any(text in result.stderr for text in (
            "No names found", "No tags can describe", "cannot describe",
        )):
            return None
        raise UpstreamError(f"{repo.slug}: describe {sha[:8]}: {result.stderr.strip()}")
    tag, _distance, _commit = result.stdout.strip().rsplit("-", 2)
    # describe's own count is an estimate across merges (ares: 149 where the
    # pin holds 143 commits the tag lacks): the exact count is rev-list's.
    counted = _git(["rev-list", "--count", f"refs/tags/{tag}..{sha}"], clone)
    if counted.returncode:
        raise UpstreamError(f"{repo.slug}: {tag}..{sha[:8]}: {counted.stderr.strip()}")
    return tag, int(counted.stdout.strip())


def graph_ancestry(
    repo: Repo, base: str, head: str, cache_dir: str, offline: bool = False
) -> tuple[int, int]:
    """(ahead, behind) counted in the commit graph, for a pair a forge
    refuses to compare (GitHub answers 422 past a diff size)."""
    clone = _graph(repo, head, cache_dir, offline)
    counts = []
    for spec in (f"{base}..{head}", f"{head}..{base}"):
        result = _git(["rev-list", "--count", spec], clone)
        if result.returncode:
            raise UpstreamError(f"{repo.slug}: {spec}: {result.stderr.strip()}")
        counts.append(int(result.stdout.strip()))
    return counts[0], counts[1]
