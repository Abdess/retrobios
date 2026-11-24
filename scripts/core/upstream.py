"""Access to upstream source repositories.

Resolves revisions and fetches files by sha across the forge families the
emulator profiles point at. Knows nothing about profile structure.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core.artifacts import write_text_atomic
from core import forgehttp
from core.offline import run_is_offline

# Where fetched upstream files live, shared by every reader of this cache.
CACHE_DIR = ".cache/upstream"
ABSENT = "\0absent\0"

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
    write_text_atomic(target, text)


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
    offline = run_is_offline(offline)
    target = cache_path(cache_dir, repo, sha, path)
    if target.is_file():
        text = target.read_text(encoding="utf-8")
        return None if text == ABSENT else text.splitlines()
    if offline:
        raise forgehttp.NotCachedError(f"{repo.slug}@{sha[:8]}:{path} is not in the offline cache")
    fetched = forgehttp.http_text(content_url(repo, sha, path))
    write_cache(target, ABSENT if fetched is None else fetched)
    return None if fetched is None else fetched.splitlines()


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

    cached_api answers None both for a resource the forge does not have and for
    one never asked, and only the first is a fact.
    """
    if run_is_offline(offline) and not _api_target(url, cache_dir).is_file():
        raise forgehttp.NotCachedError(f"{what} is not in the offline cache")


def cached_api(
    url: str, cache_dir: str, offline: bool, max_age: float | None = None,
    absent_max_age: float | None = None,
) -> object | None:
    """Cached API call. The cache stores absence as well as payloads.

    ``max_age`` bounds the trust in a cached answer, in seconds. A stale
    answer is refreshed unless the run is offline, when it still serves.
    ``absent_max_age`` bounds a cached absence alone, for a resource that
    can appear but, once there, does not change.
    """
    offline = run_is_offline(offline)
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
    payload = forgehttp.http_json(url)
    write_cache(target, ABSENT if payload is None else json.dumps(payload))
    return payload


def fetch_page(url: str, cache_dir: str, offline: bool) -> str | None:
    """A web page's text, cached like a moving API answer (MOVING_TTL).

    A project published outside a forge (Altirra, mednafen, ePSXe) says its
    version on a download page: that page is the only release feed there is.
    None is a page the site answers absent. Offline, a page the cache never
    stored raises NotCachedError, as every other read of this module does.
    """
    offline = run_is_offline(offline)
    key = hashlib.sha256(url.encode()).hexdigest()
    target = Path(cache_dir) / "_pages" / f"{key}.txt"
    if target.is_file():
        fresh = time.time() - target.stat().st_mtime <= MOVING_TTL
        if fresh or offline:
            raw = target.read_text(encoding="utf-8")
            return None if raw == ABSENT else raw
    if offline:
        raise forgehttp.NotCachedError(f"{url} is not in the offline cache")
    text = forgehttp.http_text(url)
    write_cache(target, ABSENT if text is None else text)
    return text


def project_path(repo: Repo) -> str:
    return urllib.parse.quote(f"{repo.owner}/{repo.name}", safe="")


def _commits_url(repo: Repo, date: str | None, branch: str | None = None) -> str:
    if repo.family == "github":
        base = f"{repo.api_base}/repos/{repo.slug}/commits?per_page=1"
        if branch:
            base += f"&sha={urllib.parse.quote(branch, safe='')}"
    elif repo.family == "gitlab":
        base = (
            f"{repo.api_base}/projects/{project_path(repo)}"
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
        url, key = f"{repo.api_base}/projects/{project_path(repo)}", "path_with_namespace"
    else:
        url, key = f"{repo.api_base}/repos/{repo.slug}", "full_name"
    payload = cached_api(url, cache_dir, offline, MOVING_TTL)
    if not isinstance(payload, dict):
        return None
    value = payload.get(key)
    return str(value) if value else None


def resolve_head(
    repo: Repo, cache_dir: str | None, offline: bool = False, branch: str | None = None,
    fresh: bool = False,
) -> str | None:
    """Sha of a branch tip, the default branch unless one is named. A tag
    resolves too: every forge's commit listing starts from any ref.

    A libretro port often lives on a branch of a fork rather than on the
    default branch, so the code a profile documents can be absent from the
    tip the forge serves by default. ``fresh`` asks the forge again whatever
    the cache holds. A ``cache_dir`` of None asks the forge and keeps
    nothing: a scraper records the sha it read in its own output, and an
    answer it never reads back has no place in the profile cache.

    Offline, a tip the cache never stored raises NotCachedError: returning
    None read as a branch the forge does not have, and profile_sync dropped
    xenios-jp/XeniOS, judging its citations against the other repository.
    """
    url = _commits_url(repo, None, branch)
    if cache_dir is None:
        if offline:
            raise forgehttp.NotCachedError(f"{repo.slug}: no cache to read offline")
        return _first_sha(forgehttp.http_json(url))
    _require_cached(
        url, cache_dir, offline, f"{repo.slug}: tip of {branch or 'the default branch'}"
    )
    return _first_sha(cached_api(url, cache_dir, offline, 0 if fresh else MOVING_TTL))


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
        return _first_sha(cached_api(url, cache_dir, offline))
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
        payload = cached_api(url, cache_dir, offline, MOVING_TTL)
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
            f"{repo.api_base}/projects/{project_path(repo)}"
            f"/repository/tags?per_page=100"
        )
    return f"{repo.api_base}/repos/{repo.slug}/tags?per_page=100"


def list_tags(repo: Repo, cache_dir: str, offline: bool = False) -> list[str]:
    """Tag names, newest first as the forge orders them."""
    payload = cached_api(_tags_url(repo), cache_dir, offline, MOVING_TTL)
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
    from core.github import github_token

    offline = run_is_offline(offline)
    body = json.dumps({"query": query, "variables": variables}, sort_keys=True)
    target = Path(cache_dir) / "_api" / f"{hashlib.sha256(body.encode()).hexdigest()}.json"
    if target.is_file():
        fresh = time.time() - target.stat().st_mtime <= MOVING_TTL
        if fresh or offline:
            return json.loads(target.read_text(encoding="utf-8"))
    token = github_token()
    if offline or not token:
        return None
    headers = forgehttp.forge_headers(GITHUB_GRAPHQL, "application/json")
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        GITHUB_GRAPHQL, data=body.encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise forgehttp._http_failure(GITHUB_GRAPHQL, exc) from exc
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        raise forgehttp.UpstreamError(f"{GITHUB_GRAPHQL}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("errors"):
        return None
    write_cache(target, json.dumps(payload))
    return payload


def _dig(value: object, *keys: str) -> object:
    """The value under nested keys of a JSON answer, None where one is missing."""
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


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
        nodes = _dig(payload, "data", "repository", "refs", "nodes")
        if isinstance(nodes, list):
            return nodes[0].get("name") if nodes else None
    tags = list_tags(repo, cache_dir, offline)
    return tags[0] if tags else None


def resolve_tag_commit(
    repo: Repo, tag: str, cache_dir: str, offline: bool = False
) -> str | None:
    """Commit a tag points at."""
    payload = cached_api(_tags_url(repo), cache_dir, offline, MOVING_TTL)
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
        url = f"{repo.api_base}/projects/{project_path(repo)}/repository/tags/{quoted}"
    else:
        url = f"{repo.api_base}/repos/{repo.slug}/tags/{quoted}"
    payload = cached_api(url, cache_dir, offline, absent_max_age=MOVING_TTL)
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
    payload = cached_api(
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
    annotated = cached_api(
        f"{repo.api_base}/repos/{repo.slug}/git/tags/{obj.get('sha')}",
        cache_dir,
        offline,
    )
    target = annotated.get("object") if isinstance(annotated, dict) else None
    return target.get("sha") if isinstance(target, dict) else None


def _releases_url(repo: Repo) -> str:
    if repo.family == "gitlab":
        return f"{repo.api_base}/projects/{project_path(repo)}/releases"
    return f"{repo.api_base}/repos/{repo.slug}/releases/latest"


def latest_release(
    repo: Repo, cache_dir: str, offline: bool = False
) -> Release | None:
    """Most recent release the forge exposes."""
    payload = cached_api(_releases_url(repo), cache_dir, offline, MOVING_TTL)
    if isinstance(payload, list):
        payload = payload[0] if payload else None
    if not isinstance(payload, dict):
        return None
    tag = payload.get("tag_name") or payload.get("tag") or ""
    stamp = payload.get("published_at") or payload.get("released_at") or ""
    if not tag:
        return None
    return Release(str(tag), str(stamp)[:10], bool(payload.get("prerelease")))


def commit_date(repo: Repo, sha: str, cache_dir: str, offline: bool = False) -> str | None:
    """When a revision was committed, as the forge reports it (ISO 8601)."""
    if repo.family == "gitlab":
        payload = cached_api(
            f"{repo.api_base}/projects/{project_path(repo)}/repository/commits/{sha}",
            cache_dir, offline,
        )
        value = payload.get("committed_date") if isinstance(payload, dict) else None
        return value if isinstance(value, str) else None
    if repo.family == "github":
        url = f"{repo.api_base}/repos/{repo.slug}/commits/{sha}"
    else:
        url = f"{repo.api_base}/repos/{repo.slug}/git/commits/{sha}"
    stamp = _gitea_commit_date(cached_api(url, cache_dir, offline))
    return stamp.isoformat() if stamp is not None else None


def path_commits_url(
    repo: Repo, path: str, *, per_page: int = 100,
    since: str | None = None, page: int | None = None,
) -> str:
    """The forge's listing of the commits that touch a path."""
    if repo.family == "gitlab":
        base = f"{repo.api_base}/projects/{project_path(repo)}/repository/commits"
    else:
        base = f"{repo.api_base}/repos/{repo.slug}/commits"
    url = f"{base}?path={urllib.parse.quote(path)}"
    if since is not None:
        url += f"&since={urllib.parse.quote(since)}"
    size_key = "per_page" if repo.family in ("github", "gitlab") else "limit"
    url += f"&{size_key}={per_page}"
    return url if page is None else f"{url}&page={page}"


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
    url = path_commits_url(repo, path, since=since)
    # The list grows with every push touching the path: cached for good, the
    # triage drift score stayed at whatever the first run counted.
    payload = cached_api(url, cache_dir, offline, MOVING_TTL)
    if not isinstance(payload, list):
        return 0
    return sum(
        1 for entry in payload
        if isinstance(entry, dict) and (entry.get("sha") or entry.get("id")) != base
    )
