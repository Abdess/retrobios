"""The repositories a profile declares and the field that pins each one."""

from __future__ import annotations

from core import upstream

# Read in this order: a declared repository decides attribution before the
# mirror that only keeps a gone forge's history reachable.
REPOSITORY_FIELDS = ("source", "upstream", "source_mirror")


def declared_repositories(profile: dict) -> list[tuple[str, str, str]]:
    """Every repository URL the profile declares, source before upstream,
    as (field, build mode, url).

    `source` and `upstream` are usually plain strings. `ymir` keys them by
    build mode instead, because its standalone and libretro builds live in
    different repositories.

    `source_mirror` comes last and is the only thing that keeps a profile
    checkable once its forge is gone: yuzu and suyu answer 451, citron's
    host stopped resolving. Being last, it never decides attribution while
    a declared repository still answers.
    """
    urls: list[tuple[str, str, str]] = []
    for field_name in REPOSITORY_FIELDS:
        value = profile.get(field_name)
        if isinstance(value, dict):
            urls.extend((field_name, str(k), str(v)) for k, v in value.items() if v)
        elif value:
            urls.append((field_name, "", str(value)))
    return urls


def _identity(url: str) -> tuple[str, str] | str:
    """What two URLs naming one repository share: host and slug on a known
    forge, the URL itself elsewhere."""
    repo = upstream.parse_repo(url)
    return (repo.host, repo.slug) if repo is not None else url.strip().rstrip("/")


def serving_url(profile: dict, url: str) -> str:
    """The URL that serves a declared repository: the `source_mirror` of a
    `source` the profile declares gone, the URL itself otherwise.

    The mirror carries the same commits: simple64/simple64 and
    teknogods/TeknoParrotUI answer 404, and the site linked every citation
    into them while profile_sync read the mirror. An `upstream` naming the
    gone source is served by the mirror too.
    """
    mirror = str(profile.get("source_mirror") or "")
    if not mirror or not str(profile.get("upstream_gone") or "").strip():
        return url
    gone = {_identity(u) for field, _mode, u in declared_repositories(profile) if field == "source"}
    return mirror if _identity(url) in gone else url


def pin_field(field: str) -> str:
    """The `<field>_commit` that pins a repository field. A mirror carries
    the source's history, commits and branches alike: source_commit pins it."""
    return "source" if field == "source_mirror" else field


def declared_pin(profile: dict, field: str, mode: str = "") -> tuple[str, str]:
    """The commit `<field>_commit` declares for a build mode, and the field
    it was read from, or ('', origin) when the profile declares none.

    A profile whose builds live in different repositories keys its pin by
    build mode, the way `ymir` keys `source` and `core_version`. Without a
    declared pin, the revision is the last commit by `profiled_date`, which
    only a forge (or its cache) can answer.
    """
    pinned = profile.get(f"{field}_commit")
    if isinstance(pinned, dict):
        return str(pinned.get(mode) or ""), f"{field}_commit[{mode}]"
    return str(pinned or ""), f"{field}_commit"
