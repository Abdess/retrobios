"""The upstream revision a platform YAML's `source:` URL names.

A scraper writes the URL of the file it read at the tag or commit it read
it at. The target scrapers, the launcher extractors and the exporter all
read that revision back, so the URL shapes are recognised in one place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from model.sources import source_yaml_file


@dataclass(frozen=True)
class SourceURL:
    """A forge URL split into the repository, the revision and the path."""

    host: str
    owner: str
    repo: str
    rev: str
    path: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


# A trailing file path is optional: a tree URL names the whole repository
# at a commit (RetroDECK, MinUI). A GitLab owner is the whole group path.
_SOURCE_PATTERNS = (
    re.compile(r"^https://raw\.githubusercontent\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
               r"(?P<rev>[^/]+)(?:/(?P<path>.*))?$"),
    re.compile(r"^https://(?P<host>github\.com)/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
               r"(?:blob|tree)/(?P<rev>[^/]+)(?:/(?P<path>.*))?$"),
    re.compile(r"^https://(?P<host>gitlab\.com)/(?P<owner>.+?)/(?P<repo>[^/]+)/-/"
               r"(?:raw|blob|tree)/(?P<rev>[^/]+)(?:/(?P<path>.*))?$"),
    re.compile(r"^https://(?P<host>gitlab\.com)/(?P<owner>.+?)/(?P<repo>[^/]+)/-/"
               r"archive/(?P<rev>[^/]+)(?:/.*)?$"),
    re.compile(r"^https://codeload\.github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
               r"(?:tar\.gz|zip)/(?P<rev>[^/]+)$"),
    re.compile(r"^https://(?P<host>github\.com)/(?P<owner>[^/]+)/(?P<repo>[^/]+?)/?$"),
)
_COMMIT = re.compile(r"[0-9a-f]{40}")


def parse_source(url: str) -> SourceURL | None:
    """The forge, repository, revision and path a forge URL names, None
    when it is no shape a scraper pins. A bare repository has rev ''."""
    url = str(url or "").strip()
    for pattern in _SOURCE_PATTERNS:
        match = pattern.match(url)
        if match:
            parts = match.groupdict()
            return SourceURL(
                parts.get("host") or "github.com", parts["owner"], parts["repo"],
                parts.get("rev") or "", (parts.get("path") or "").rstrip("/"),
            )
    return None


def source_revision(url: str) -> str:
    """The tag or commit a forge URL is read at, '' when it names none."""
    parsed = parse_source(url)
    return parsed.rev if parsed else ""


def _names_repo(url: str, repo: str) -> bool:
    """`url` is a URL of `repo` (owner/name, compared without case as the
    forges do)."""
    parsed = parse_source(url)
    return parsed is not None and parsed.slug.lower() == repo.lower()


def required_revision(url: str, repo: str = "", commit: bool = False) -> str:
    """The revision `url` names, ValueError when it names none.

    `repo` (owner/name) refuses a URL of another repository, `commit`
    refuses a tag or a branch where only a commit pins the read.
    """
    revision = source_revision(url)
    if repo and not _names_repo(url, repo):
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
    source = _platform_source(platform_file)
    try:
        return required_revision(source, repo, commit)
    except ValueError as exc:
        raise RuntimeError(
            f"platforms/{platform_file.name} names no pinned revision in its "
            f"source ({source!r}): rescrape the platform first"
        ) from exc


def _platform_source(platform_file: Path) -> str:
    return str((source_yaml_file(platform_file) or {}).get("source") or "")


def scraped_revision(platform_file: Path, repo: str = "") -> str:
    """The revision a platform YAML was scraped at, '' when the file is
    absent, its source names none or names another repository than `repo`."""
    if not platform_file.is_file():
        return ""
    source = _platform_source(platform_file)
    if repo and not _names_repo(source, repo):
        return ""
    return source_revision(source)
