"""Trees of upstream revisions: what changed between two, listings, gitlinks and local clone history."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from core import forgehttp, upstream
from core.offline import run_is_offline


GITHUB_COMPARE_CAP = 300


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


def _compare_url(repo: upstream.Repo, base: str, head: str) -> str:
    if repo.family == "gitlab":
        return (
            f"{repo.api_base}/projects/{upstream.project_path(repo)}"
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
    repo: upstream.Repo, base: str, head: str, cache_dir: str, offline: bool = False
) -> CompareResult:
    """Tree difference between two revisions."""
    payload = upstream.cached_api(_compare_url(repo, base, head), cache_dir, offline)
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
    repo: upstream.Repo, sha: str, fork: upstream.Repo, fork_sha: str, cache_dir: str,
    offline: bool = False,
) -> str | None:
    """The commit of ``repo`` that ``fork`` at ``fork_sha`` has merged up to.

    GitHub compares across a fork network and names the merge base. Two
    repositories outside one network answer 404, and None is returned.
    """
    if repo.family != "github" or fork.family != "github":
        return None
    payload = upstream.cached_api(
        f"{repo.api_base}/repos/{repo.slug}/compare/"
        f"{sha}...{fork.owner}:{fork.name}:{fork_sha}",
        cache_dir, offline,
    )
    base = payload.get("merge_base_commit") if isinstance(payload, dict) else None
    return base.get("sha") if isinstance(base, dict) else None


def ancestry(
    repo: upstream.Repo, base: str, head: str, cache_dir: str, offline: bool = False
) -> tuple[int, int] | None:
    """(ahead, behind): commits head has that base lacks, and the reverse.

    Two shas never change their history, so both answers are cached for
    good. GitHub gives both counts in one answer, GitLab and Forgejo list
    one direction only and are asked twice.
    """
    forward = upstream.cached_api(_compare_url(repo, base, head), cache_dir, offline)
    ahead = _commits_ahead(forward, repo.family)
    if ahead is None:
        return None
    if repo.family == "github":
        behind = forward.get("behind_by") if isinstance(forward, dict) else None
    else:
        behind = _commits_ahead(
            upstream.cached_api(_compare_url(repo, head, base), cache_dir, offline), repo.family
        )
    return (ahead, behind) if isinstance(behind, int) else None


def find_renamed(result: CompareResult, path: str) -> str | None:
    """New path of a file the comparison reports as renamed."""
    for change in result.files:
        if change.status == "renamed" and change.previous_path == path:
            return change.path
    return None


def _tree_url(repo: upstream.Repo, sha: str) -> str | None:
    if repo.family == "gitlab":
        return None
    return f"{repo.api_base}/repos/{repo.slug}/git/trees/{sha}?recursive=1"


def list_directory(
    repo: upstream.Repo, sha: str, path: str, cache_dir: str, offline: bool = False
) -> list[str] | None:
    """Names of the blobs directly under one directory at one revision.

    One request for the directory alone, where the whole tree of a large
    repository comes back truncated. None when the forge has no such call
    or the directory does not exist there.
    """
    if repo.family != "github":
        return None
    url = f"{repo.api_base}/repos/{repo.slug}/git/trees/{sha}:{path.strip('/')}"
    payload = upstream.cached_api(url, cache_dir, offline)
    if not isinstance(payload, dict) or payload.get("truncated"):
        return None
    return sorted(
        entry["path"]
        for entry in payload.get("tree") or []
        if isinstance(entry, dict) and entry.get("type") == "blob" and entry.get("path")
    )


TREE_PAGE_SIZE = 100
MAX_TREE_PAGES = 50


def gitlab_tree_entries(
    repo: upstream.Repo, sha: str, cache_dir: str, offline: bool, *,
    path: str | None = None, recursive: bool = True,
) -> tuple[list[dict], bool]:
    """The entries of a GitLab tree at a revision, and whether the listing
    is truncated. GitLab serves its tree in pages, each page cached on its
    own URL.

    A page that cannot be read mid-walk, or the page cap, reports the
    listing as truncated: the entries already collected are real, but an
    absence proves nothing.
    """
    entries: list[dict] = []
    scope = "" if path is None else f"&path={path}"
    for page in range(1, MAX_TREE_PAGES + 1):
        url = (
            f"{repo.api_base}/projects/{upstream.project_path(repo)}/repository/tree"
            f"?ref={sha}{scope}&recursive={'true' if recursive else 'false'}"
            f"&per_page={TREE_PAGE_SIZE}&page={page}"
        )
        payload = upstream.cached_api(url, cache_dir, offline)
        if not isinstance(payload, list):
            return entries, True
        entries.extend(entry for entry in payload if isinstance(entry, dict))
        if len(payload) < TREE_PAGE_SIZE:
            return entries, False
    return entries, True


def cache_gitlab_directory(
    repo: upstream.Repo, sha: str, directory: str, cache_dir: str, offline: bool = False
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
    index = upstream.cache_path(cache_dir, repo, sha, f".archives/{directory}.json")
    if index.is_file():
        return set(json.loads(index.read_text(encoding="utf-8")))
    if run_is_offline(offline) or repo.family != "gitlab":
        return None
    try:
        files = _gitlab_archive_files(repo, sha, directory)
    except forgehttp.RateLimitError:
        files = _sparse_git_files(repo, sha, directory, cache_dir)
    if not files:
        raise forgehttp.UpstreamError(f"{repo.slug}@{sha[:8]}: nothing under {directory}")
    for path, text in files.items():
        upstream.write_cache(upstream.cache_path(cache_dir, repo, sha, path), text)
    upstream.write_cache(index, json.dumps(sorted(files)))
    return set(files)


def _gitlab_archive_files(repo: upstream.Repo, sha: str, directory: str) -> dict[str, str]:
    url = (
        f"{repo.api_base}/projects/{upstream.project_path(repo)}/repository/archive.tar.gz"
        f"?sha={sha}&path={urllib.parse.quote(directory)}"
    )
    body = forgehttp.fetch_body(url)
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


def _sparse_git_files(repo: upstream.Repo, sha: str, directory: str, cache_dir: str) -> dict[str, str]:
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
                raise forgehttp.UpstreamError(f"{url}: git {argv[0]} failed: {result.stderr.strip()}")
        root = work / directory
        return {
            f"{directory}/{p.relative_to(root).as_posix()}": p.read_text(encoding="utf-8", errors="replace")
            for p in sorted(root.rglob("*")) if p.is_file()
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _tree_entries(
    repo: upstream.Repo, sha: str, cache_dir: str, offline: bool
) -> tuple[list[dict], bool] | None:
    """Every entry of the tree at one revision, and whether the forge served
    it in part. None when the forge serves no tree for it."""
    if repo.family == "gitlab":
        return gitlab_tree_entries(repo, sha, cache_dir, offline)
    url = _tree_url(repo, sha)
    if url is None:
        return None
    payload = upstream.cached_api(url, cache_dir, offline)
    if not isinstance(payload, dict):
        return None
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
            more = upstream.cached_api(f"{url}&page={page}", cache_dir, offline)
            if not isinstance(more, dict) or not more.get("tree"):
                break
            entries.extend(more["tree"])
        truncated = len(entries) < total
    return [entry for entry in entries if isinstance(entry, dict)], truncated


def list_tree(
    repo: upstream.Repo, sha: str, cache_dir: str, offline: bool = False
) -> tuple[list[str], bool]:
    """Every blob path at one revision, and whether the forge truncated it."""
    listing = _tree_entries(repo, sha, cache_dir, offline)
    if listing is None:
        return [], True
    entries, truncated = listing
    paths = [
        entry["path"] for entry in entries
        if entry.get("type") == "blob" and entry.get("path")
    ]
    return paths, truncated


def list_gitlinks(
    repo: upstream.Repo, sha: str, cache_dir: str, offline: bool = False
) -> dict[str, str]:
    """Submodule path -> the commit it points at, at one revision.

    Read from the same tree listing as list_tree, so the call costs nothing
    once the tree is cached. A listing the forge served in part raises
    TruncatedListingError: a partial answer read as "no submodule there",
    and a port then lost the upstream commit its gitlink pins.
    """
    listing = _tree_entries(repo, sha, cache_dir, offline)
    if listing is None:
        return {}
    entries, truncated = listing
    if truncated:
        raise forgehttp.TruncatedListingError(f"{repo.slug}@{sha[:8]}: tree listing truncated")
    # GitLab names the target commit `id`, GitHub and Forgejo `sha`.
    key = "id" if repo.family == "gitlab" else "sha"
    return {
        entry["path"]: entry[key]
        for entry in entries
        if entry.get("type") == "commit" and entry.get("path") and entry.get(key)
    }


def submodule_urls(text: str, base: upstream.Repo) -> dict[str, upstream.Repo]:
    """Submodule path -> repository, read from a .gitmodules text.

    A relative url (`../xash3d-fwgs.git`) names a sibling of the repository
    that declares it, on the same forge.
    """
    repos: dict[str, upstream.Repo] = {}
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
                repo = upstream.parse_repo(url)
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
    repo: upstream.Repo, sha: str, path: str, cache_dir: str, offline: bool = False
) -> tuple[upstream.Repo, str, str] | None:
    """The submodule repository, commit and inner path a path falls under.

    starship cites `Torch src/Companion.cpp`, a file of the Torch submodule:
    the declared tree holds only the gitlink, which pins the revision.
    """
    links = list_gitlinks(repo, sha, cache_dir, offline)
    link = next((p for p in links if path.startswith(p + "/")), None)
    if link is None:
        return None
    modules = upstream.fetch_file(repo, sha, ".gitmodules", cache_dir, offline)
    target = submodule_urls("\n".join(modules or ()), repo).get(link)
    if target is None:
        return None
    return target, links[link], path[len(link) + 1:]


# Commit graphs kept to count the commits between a tag and a pin. A
# treeless bare clone holds commits and tags only: the files a profile reads
# come from fetch_file, by sha.
GIT_DIR = "_git"


def clone_dir(cache_dir: str, repo: upstream.Repo) -> Path:
    """Where the commit graph of a repository is kept."""
    return Path(cache_dir) / GIT_DIR / repo.host / repo.owner / f"{repo.name}.git"


def _git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, env=env, check=False
    )


def _has_commit(clone: Path, sha: str) -> bool:
    return _git(["cat-file", "-e", f"{sha}^{{commit}}"], clone).returncode == 0


def _graph(repo: upstream.Repo, sha: str, cache_dir: str, offline: bool) -> Path:
    """A clone holding sha and every tag, fetched again once tags may have moved."""
    offline = run_is_offline(offline)
    clone = clone_dir(cache_dir, repo)
    url = f"https://{repo.host}/{repo.slug}.git"
    if not (clone / "HEAD").is_file():
        if offline:
            raise forgehttp.NotCachedError(f"{repo.slug}: no commit graph in the offline cache")
        clone.parent.mkdir(parents=True, exist_ok=True)
        result = _git(["clone", "--quiet", "--bare", "--filter=tree:0", url, str(clone)])
        if result.returncode:
            raise forgehttp.UpstreamError(f"{url}: clone failed: {result.stderr.strip()}")
        _git(["fetch", "--quiet", "--filter=tree:0", "--tags", "origin"], clone)
    stamp = clone / "FETCH_HEAD"
    fresh = stamp.is_file() and time.time() - stamp.stat().st_mtime <= upstream.MOVING_TTL
    if offline or (fresh and _has_commit(clone, sha)):
        if not _has_commit(clone, sha):
            raise forgehttp.NotCachedError(f"{repo.slug}@{sha[:8]}: not in the offline commit graph")
        return clone
    # Tags are fetched again: a tag pushed since the clone can be nearer.
    result = _git(
        ["fetch", "--quiet", "--filter=tree:0", "--force", "--tags", "origin",
         "+refs/heads/*:refs/heads/*"], clone,
    )
    if result.returncode:
        raise forgehttp.UpstreamError(f"{url}: fetch failed: {result.stderr.strip()}")
    if not _has_commit(clone, sha):
        # A commit no branch reaches any more: a rewritten fork, a PR head.
        _git(["fetch", "--quiet", "--filter=tree:0", "origin", sha], clone)
    if not _has_commit(clone, sha):
        raise forgehttp.UpstreamError(f"{url}: {sha[:8]} is on no branch the forge serves")
    return clone


def describe(
    repo: upstream.Repo, sha: str, cache_dir: str, offline: bool = False,
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
        raise forgehttp.UpstreamError(f"{repo.slug}: describe {sha[:8]}: {result.stderr.strip()}")
    tag, _distance, _commit = result.stdout.strip().rsplit("-", 2)
    # describe's own count is an estimate across merges (ares: 149 where the
    # pin holds 143 commits the tag lacks): the exact count is rev-list's.
    counted = _git(["rev-list", "--count", f"refs/tags/{tag}..{sha}"], clone)
    if counted.returncode:
        raise forgehttp.UpstreamError(f"{repo.slug}: {tag}..{sha[:8]}: {counted.stderr.strip()}")
    return tag, int(counted.stdout.strip())


def graph_ancestry(
    repo: upstream.Repo, base: str, head: str, cache_dir: str, offline: bool = False
) -> tuple[int, int]:
    """(ahead, behind) counted in the commit graph, for a pair a forge
    refuses to compare (GitHub answers 422 past a diff size)."""
    clone = _graph(repo, head, cache_dir, offline)
    counts = []
    for spec in (f"{base}..{head}", f"{head}..{base}"):
        result = _git(["rev-list", "--count", spec], clone)
        if result.returncode:
            raise forgehttp.UpstreamError(f"{repo.slug}: {spec}: {result.stderr.strip()}")
        counts.append(int(result.stdout.strip()))
    return counts[0], counts[1]
