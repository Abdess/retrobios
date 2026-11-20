"""The upstream revision a platform YAML's `source:` URL names.

A scraper writes the URL of the file it read at the tag or commit it read
it at. The target scrapers, the launcher extractors and the exporter all
read that revision back, so the URL shapes are recognised in one place.
"""

from __future__ import annotations

import re
from pathlib import Path

from model.sources import source_yaml_file

# Each pattern captures the revision. A trailing file path is optional: a
# tree URL names the whole repository at a commit (RetroDECK, MinUI).
_REVISION_PATTERNS = (
    re.compile(r"^https://raw\.githubusercontent\.com/[^/]+/[^/]+/([^/]+)(?:/|$)"),
    re.compile(r"^https://github\.com/[^/]+/[^/]+/(?:blob|tree)/([^/]+)(?:/|$)"),
    re.compile(r"^https://gitlab\.com/.+?/-/(?:raw|blob|tree|archive)/([^/]+)(?:/|$)"),
    re.compile(r"^https://codeload\.github\.com/[^/]+/[^/]+/(?:tar\.gz|zip)/([^/]+)$"),
)
_COMMIT = re.compile(r"[0-9a-f]{40}")


def source_revision(url: str) -> str:
    """The tag or commit a forge URL is read at, '' when it names none."""
    for pattern in _REVISION_PATTERNS:
        match = pattern.match(url)
        if match:
            return match.group(1)
    return ""


def required_revision(url: str, repo: str = "", commit: bool = False) -> str:
    """The revision `url` names, ValueError when it names none.

    `repo` (owner/name) refuses a URL of another repository, `commit`
    refuses a tag or a branch where only a commit pins the read.
    """
    revision = source_revision(url)
    if repo and f"/{repo}/" not in url:
        revision = ""
    if commit and not _COMMIT.fullmatch(revision):
        revision = ""
    if not revision:
        kind = "commit" if commit else "revision"
        raise ValueError(f"{url} names no {repo + ' ' if repo else ''}{kind}")
    return revision


def platform_revision(platform_file: Path, repo: str = "", commit: bool = False) -> str:
    """The revision a platform YAML was scraped at, RuntimeError when its
    source names none (`repo` and `commit` as for required_revision).

    A target list or a launcher extraction describes the same release as
    the platform's BIOS list: moving to a new release is a rescrape of the
    platform first.
    """
    source = str((source_yaml_file(platform_file) or {}).get("source") or "")
    try:
        return required_revision(source, repo, commit)
    except ValueError as exc:
        raise RuntimeError(
            f"platforms/{platform_file.name} names no pinned revision in its "
            f"source ({source!r}): rescrape the platform first"
        ) from exc
