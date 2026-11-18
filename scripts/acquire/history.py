"""The upstream revision whose copy of a file has a pinned md5, found by walking the file's history."""

from __future__ import annotations

import hashlib
import urllib.parse

from core import upstream


# Commits listed per page and the most pages walked: a data file older than
# 2 000 commits on its own path is not one a platform list still pins.
PER_PAGE = 100
MAX_PAGES = 20


def _history_url(repo: upstream.Repo, path: str, page: int) -> str:
    quoted = urllib.parse.quote(path)
    if repo.family == "gitlab":
        project = urllib.parse.quote(repo.slug, safe="")
        return (f"{repo.api_base}/projects/{project}/repository/commits"
                f"?path={quoted}&per_page={PER_PAGE}&page={page}")
    if repo.family == "github":
        return (f"{repo.api_base}/repos/{repo.slug}/commits"
                f"?path={quoted}&per_page={PER_PAGE}&page={page}")
    return (f"{repo.api_base}/repos/{repo.slug}/commits"
            f"?path={quoted}&limit={PER_PAGE}&page={page}")


def path_history(repo: upstream.Repo, path: str, cache_dir: str) -> list[str]:
    """Commits that touched a path, newest first."""
    shas: list[str] = []
    for page in range(1, MAX_PAGES + 1):
        payload = upstream._api(_history_url(repo, path, page), cache_dir, False,
                                max_age=upstream.MOVING_TTL)
        if not isinstance(payload, list) or not payload:
            break
        shas += [str(entry.get("sha") or entry.get("id")) for entry in payload]
        if len(payload) < PER_PAGE:
            break
    return shas


def find_revision(
    repo: upstream.Repo, path: str, md5: str, cache_dir: str,
) -> tuple[str, bytes] | None:
    """The newest revision whose copy of the path has this md5, and its bytes."""
    wanted = md5.lower()
    for sha in path_history(repo, path, cache_dir):
        data = upstream._fetch(upstream.content_url(repo, sha, path))
        if data is not None and hashlib.md5(data).hexdigest() == wanted:
            return sha, data
    return None
