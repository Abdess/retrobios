"""The pins of platforms/romfolders/_sources/ against what they follow."""

from __future__ import annotations

from pathlib import Path

from core import upstream
from model.registry import load_platform_registry
from model.sources import source_yaml_file
from model.sourcerevision import scraped_revision
from freshness.findings import OK, SKIPPED, STALE, UNKNOWN, Finding


def romfolder_sources(platforms_dir: Path) -> dict[str, dict]:
    """setup -> its platforms/romfolders/_sources/<setup>.yml."""
    out = {}
    for path in sorted((platforms_dir / "romfolders" / "_sources").glob("*.yml")):
        out[path.stem] = source_yaml_file(path) or {}
    return out


def _os_source(doc: dict) -> dict:
    """The source the setup is pinned on: `os`, else the first declared.
    The others follow from it (an EmulationStation pinned by a package.mk)."""
    sources = doc.get("sources") or {}
    return sources.get("os") or next(iter(sources.values()), {})


def platform_revision(setup: str, doc: dict, platforms_dir: Path) -> str:
    """The revision the setup's own platform file was scraped at, when the
    setup is a registered platform read from the same repository; '' else."""
    if setup not in load_platform_registry(str(platforms_dir)):
        return ""
    repo = upstream.parse_repo(str(_os_source(doc).get("repo") or ""))
    if repo is None:
        return ""
    return scraped_revision(platforms_dir / f"{setup}.yml", repo.slug)


def romfolder_pin_drift(setup: str, doc: dict, platforms_dir: Path) -> str | None:
    """Why the folders and the BIOS of one platform come from two revisions,
    None when they do not or when only the forge can tell (a tag on one
    side, a commit on the other)."""
    revision = platform_revision(setup, doc, platforms_dir)
    os_source = _os_source(doc)
    tag, commit = os_source.get("tag"), str(os_source.get("commit") or "")
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
    """
    findings: list[Finding] = []
    for setup, doc in romfolder_sources(platforms_dir).items():
        os_source = _os_source(doc)
        pin = str(os_source.get("tag") or str(os_source.get("commit") or "")[:12])
        drift = romfolder_pin_drift(setup, doc, platforms_dir)
        if drift:
            findings.append(Finding("romfolders", setup, STALE, local=pin, detail=drift))
            continue
        revision = platform_revision(setup, doc, platforms_dir)
        repo = upstream.parse_repo(str(os_source.get("repo") or ""))
        commit = str(os_source.get("commit") or "")
        if revision and revision in (os_source.get("tag"), commit):
            findings.append(Finding("romfolders", setup, OK, local=pin,
                                    detail=f"read where platforms/{setup}.yml is"))
            continue
        if offline:
            findings.append(Finding("romfolders", setup, SKIPPED, local=pin, detail="offline"))
            continue
        if repo is None or not commit:
            findings.append(Finding("romfolders", setup, UNKNOWN, local=pin, detail="no forge to ask"))
            continue
        findings.append(_romfolder_upstream(setup, repo, os_source, revision, cache_dir))
    return findings


def _romfolder_upstream(
    setup: str, repo: upstream.Repo, os_source: dict, revision: str, cache_dir: str,
) -> Finding:
    commit, tag = str(os_source["commit"]), os_source.get("tag")
    pin = str(tag or commit[:12])
    if revision:
        # The platform names a tag and the setup a commit: the tag's commit decides.
        tagged = upstream.resolve_tag_commit(repo, revision, cache_dir)
        if tagged is None:
            return Finding("romfolders", setup, UNKNOWN, local=pin, detail=f"tag {revision} not listed")
        if tagged == commit:
            return Finding("romfolders", setup, OK, local=pin, detail=f"commit of {revision}")
        return Finding("romfolders", setup, STALE, local=pin, remote=revision,
                       detail=f"platforms/{setup}.yml was scraped at {revision} ({tagged[:12]})")
    pinned_at = (upstream.commit_date(repo, commit, cache_dir) or "")[:10]
    release = upstream.latest_release(repo, cache_dir)
    if release is not None and release.date:
        newer = release.tag != tag and release.date > pinned_at
        return Finding("romfolders", setup, STALE if newer else OK, local=f"{pin} ({pinned_at})",
                       remote=f"{release.tag} ({release.date})",
                       detail="a release is newer than the pin" if newer else "newest release")
    head = upstream.resolve_head(repo, cache_dir)
    if head is None:
        return Finding("romfolders", setup, UNKNOWN, local=pin, detail="branch head unavailable")
    if head == commit:
        return Finding("romfolders", setup, OK, local=pin, detail="branch head")
    counts = upstream.ancestry(repo, commit, head, cache_dir)
    behind = f"{counts[0]} commits behind the branch head" if counts else "the branch head moved"
    return Finding("romfolders", setup, STALE, local=pin, remote=head[:12], detail=behind)
