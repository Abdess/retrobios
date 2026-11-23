"""The pins of platforms/romfolders/_sources/ against what they follow."""

from __future__ import annotations

from pathlib import Path

from core import upstream
from model.registry import load_platform_registry
from model.romfolders import row_sources
from model.sources import source_yaml_file
from model.sourcerevision import scraped_revision
from freshness.findings import OK, SKIPPED, STALE, UNKNOWN, Finding


def romfolder_sources(platforms_dir: Path) -> dict[str, dict]:
    """setup -> its platforms/romfolders/_sources/<setup>.yml."""
    out = {}
    for path in sorted((platforms_dir / "romfolders" / "_sources").glob("*.yml")):
        out[path.stem] = source_yaml_file(path) or {}
    return out


def watched_sources(doc: dict) -> list[str]:
    """The declared sources whose pins are compared: the setup's own pin
    (`os`, else the first declared), then every source its rows are read
    from. A source that only follows another (an EmulationStation pinned by
    a package.mk) is not compared on its own."""
    sources = doc.get("sources") or {}
    own = ["os"] if "os" in sources else list(sources)[:1]
    return list(dict.fromkeys(own + [k for k in row_sources(doc) if k in sources]))


def _subject(setup: str, doc: dict, key: str) -> str:
    """The setup names the first watched pin, `setup:key` each other one."""
    return setup if key == watched_sources(doc)[0] else f"{setup}:{key}"


def platform_revision(setup: str, source: dict, platforms_dir: Path) -> str:
    """The revision the setup's own platform file was scraped at, when the
    setup is a registered platform read from the same repository; '' else."""
    if setup not in load_platform_registry(str(platforms_dir)):
        return ""
    repo = upstream.parse_repo(str(source.get("repo") or ""))
    if repo is None:
        return ""
    return scraped_revision(platforms_dir / f"{setup}.yml", repo.slug)


def romfolder_pin_drift(setup: str, source: dict, platforms_dir: Path) -> str | None:
    """Why the folders and the BIOS of one platform come from two revisions,
    None when they do not or when only the forge can tell (a tag on one
    side, a commit on the other). `source` is one declared source of the
    setup: only one read from the platform file's repository can drift."""
    revision = platform_revision(setup, source, platforms_dir)
    tag, commit = source.get("tag"), str(source.get("commit") or "")
    if not revision or revision in (tag, commit):
        return None
    if tag or len(revision) == len(commit):
        return f"platforms/{setup}.yml was scraped at {revision[:12]}, the rom folders at {tag or commit[:12]}"
    return None


def check_romfolders(platforms_dir: Path, cache_dir: str, offline: bool) -> list[Finding]:
    """The pins of platforms/romfolders/_sources/ against what they follow.

    A setup that is a registered platform is read at the revision its
    platform file was scraped at: the games-on-card mode otherwise installs
    the BIOS of one release for the folders of another. Any other setup is
    compared with its project's newest release, or with its branch head
    when the project publishes none. A pin is moved by hand, then
    `python -m scripts.scraper.romfolders --setup NAME` reads it again.
    Each watched source is one row, the second and later named `setup:key`.
    """
    return [
        _romfolder_pin(_subject(setup, doc, key), setup, doc["sources"][key], platforms_dir, cache_dir, offline)
        for setup, doc in romfolder_sources(platforms_dir).items()
        for key in watched_sources(doc)
    ]


def _romfolder_pin(
    subject: str, setup: str, source: dict, platforms_dir: Path, cache_dir: str, offline: bool,
) -> Finding:
    """One declared source's pin against the platform file, else its forge."""
    pin = str(source.get("tag") or str(source.get("commit") or "")[:12])
    drift = romfolder_pin_drift(setup, source, platforms_dir)
    if drift:
        return Finding("romfolders", subject, STALE, local=pin, detail=drift)
    revision = platform_revision(setup, source, platforms_dir)
    repo = upstream.parse_repo(str(source.get("repo") or ""))
    commit = str(source.get("commit") or "")
    if revision and revision in (source.get("tag"), commit):
        return Finding("romfolders", subject, OK, local=pin, detail=f"read where platforms/{setup}.yml is")
    if offline:
        return Finding("romfolders", subject, SKIPPED, local=pin, detail="offline")
    if repo is None or not commit:
        return Finding("romfolders", subject, UNKNOWN, local=pin, detail="no forge to ask")
    return _romfolder_upstream(setup, subject, repo, source, revision, cache_dir)


def _romfolder_upstream(
    setup: str, subject: str, repo: upstream.Repo, source: dict, revision: str, cache_dir: str,
) -> Finding:
    commit, tag = str(source["commit"]), source.get("tag")
    pin = str(tag or commit[:12])
    if revision:
        # The platform names a tag and the setup a commit: the tag's commit decides.
        tagged = upstream.resolve_tag_commit(repo, revision, cache_dir)
        if tagged is None:
            return Finding("romfolders", subject, UNKNOWN, local=pin, detail=f"tag {revision} not listed")
        if tagged == commit:
            return Finding("romfolders", subject, OK, local=pin, detail=f"commit of {revision}")
        return Finding("romfolders", subject, STALE, local=pin, remote=revision,
                       detail=f"platforms/{setup}.yml was scraped at {revision} ({tagged[:12]})")
    pinned_at = (upstream.commit_date(repo, commit, cache_dir) or "")[:10]
    release = upstream.latest_release(repo, cache_dir)
    if release is not None and release.date:
        newer = release.tag != tag and release.date > pinned_at
        return Finding("romfolders", subject, STALE if newer else OK, local=f"{pin} ({pinned_at})",
                       remote=f"{release.tag} ({release.date})",
                       detail="a release is newer than the pin" if newer else "newest release")
    head = upstream.resolve_head(repo, cache_dir)
    if head is None:
        return Finding("romfolders", subject, UNKNOWN, local=pin, detail="branch head unavailable")
    if head == commit:
        return Finding("romfolders", subject, OK, local=pin, detail="branch head")
    counts = upstream.ancestry(repo, commit, head, cache_dir)
    behind = f"{counts[0]} commits behind the branch head" if counts else "the branch head moved"
    return Finding("romfolders", subject, STALE, local=pin, remote=head[:12], detail=behind)
