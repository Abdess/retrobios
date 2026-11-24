"""Each profile's pin_build read again where its platform now stands."""

from __future__ import annotations

import re
from pathlib import Path

from core import upstream
from core import forgehttp
from core import upstreamtree
from model.sourcerevision import scraped_revision
from freshness.findings import OK, SHOWN_NAMES, SKIPPED, STALE, UNKNOWN, Finding


def build_variable(lines: list[str], variable: str) -> str | None:
    """The value the first assignment to ``variable`` gives in a build file.

    Read as a Buildroot .mk (`X_VERSION = sha`), a LibreELEC package.mk
    (`PKG_VERSION="sha"`) or a RetroPie scriptmodule (`rp_module_repo="git
    URL tag"`, `local version="20250829"`): quotes and a trailing comment go,
    the rest is compared as written.
    """
    assignment = re.compile(
        rf"^\s*(?:local\s+|export\s+)?{re.escape(variable)}\s*[:?+]?=\s*(.*)$"
    )
    for line in lines:
        match = assignment.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if value[:1] in "\"'":
            end = value.find(value[0], 1)
            return value[1:end] if end > 0 else value[1:]
        return value.split(" #", 1)[0].strip()
    return None


def pin_build_revision(reference: dict, platforms_dir: Path) -> str:
    """The revision of the platform repository its YAML was last scraped at,
    '' when the platform is not registered or reads another repository."""
    repo = upstream.parse_repo(str(reference.get("repo") or ""))
    if repo is None:
        return ""
    return scraped_revision(platforms_dir / f"{reference.get('platform', '')}.yml", repo.slug)


def check_pin_builds(
    profiles: dict, platforms_dir: Path, cache_dir: str, offline: bool,
) -> list[Finding]:
    """Each `pin_build:` read again where the platform now stands.

    A pin_frozen pin is held because one platform builds that revision, and
    nothing read the build file again: Recalbox moving mame0278 to another
    commit left the profile describing a build no platform ships. The file
    is read at the revision the platform's own YAML was scraped at, or at
    the repository's branch head for a platform this repository does not
    scrape, and its variable compared with the value the profile recorded.
    """
    findings: list[Finding] = []
    unreferenced = sorted(
        name for name, profile in profiles.items()
        if profile.get("pin_frozen") and not profile.get("pin_build")
    )
    if unreferenced:
        findings.append(Finding(
            "profiles", "pin_frozen without pin_build", SKIPPED,
            local=f"{len(unreferenced)} profiles",
            detail="no platform build file names their revision: "
                   + ", ".join(unreferenced[:SHOWN_NAMES])
                   + (", ..." if len(unreferenced) > SHOWN_NAMES else ""),
            items=unreferenced,
        ))
    for name, profile in sorted(profiles.items()):
        for reference in profile.get("pin_build") or []:
            subject = f"{name} ({reference['platform']})"
            recorded = str(reference["value"])
            revision = pin_build_revision(reference, platforms_dir)
            if revision == str(reference["revision"]):
                findings.append(Finding(
                    "profiles", subject, OK, local=recorded[:12],
                    detail=f"read where platforms/{reference['platform']}.yml is",
                ))
                continue
            repo = upstream.parse_repo(str(reference["repo"]))
            try:
                at = revision or upstream.resolve_head(repo, cache_dir, offline)
                lines = upstream.fetch_file(repo, at, reference["path"], cache_dir, offline) \
                    if at else None
                if at and lines is None:
                    # A file of a submodule is read at the commit the
                    # platform's tree pins: KNULLI builds Batocera's
                    # amiberry package through its batocera submodule.
                    modules = upstream.fetch_file(repo, at, ".gitmodules", cache_dir, offline)
                    declared = upstreamtree.submodule_urls("\n".join(modules or ()), repo)
                    if any(reference["path"].startswith(f"{p}/") for p in declared):
                        linked = upstreamtree.through_gitlink(repo, at, reference["path"],
                                                          cache_dir, offline)
                        if linked is not None:
                            lines = upstream.fetch_file(*linked, cache_dir, offline)
            except forgehttp.NotCachedError:
                findings.append(Finding("profiles", subject, SKIPPED, local=recorded[:12],
                                        detail="offline, the build file is not cached"))
                continue
            except forgehttp.UpstreamError as exc:
                findings.append(Finding("profiles", subject, UNKNOWN, local=recorded[:12],
                                        detail=str(exc)))
                continue
            if not at:
                findings.append(Finding("profiles", subject, UNKNOWN, local=recorded[:12],
                                        detail=f"{repo.slug} answered no branch head"))
                continue
            current = None if lines is None else build_variable(lines, reference["variable"])
            if current == recorded:
                findings.append(Finding(
                    "profiles", subject, OK, local=recorded[:12], remote=at[:12],
                    detail=f"{reference['path']} still builds it",
                ))
                continue
            findings.append(Finding(
                "profiles", subject, STALE, local=recorded[:12],
                remote=(current or "gone")[:12],
                detail=(
                    f"{reference['path']} is gone at {at[:12]}" if lines is None
                    else f"{reference['variable']} is no longer set there" if current is None
                    else f"{reference['platform']} now builds {current} "
                         f"({reference['path']} at {at[:12]}): the pin follows the build"
                ),
            ))
    return findings
