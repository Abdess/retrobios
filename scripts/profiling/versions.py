"""The version a profile declares against the version upstream publishes."""

from __future__ import annotations

import re
from dataclasses import dataclass

from core import upstream
from profiling.versionbasis import VersionTag, declared


@dataclass(frozen=True)
class VersionReport:
    declared: str
    latest_tag: str | None
    latest_release: str | None
    release_date: str | None
    tag_matches_declared: bool
    tag_commit: str | None
    # The tag core_version names and the commits the pin sits past it: a tag
    # basis writes 2.9.2-77-gfc4ab0b for tag 2.9.2 at distance 77.
    tag: str = ""
    distance: int = 0

    @property
    def named(self) -> str:
        """The tag name core_version stands for."""
        return self.tag or self.declared


def check_version(
    named: VersionTag, cache_dir: str, offline: bool
) -> VersionReport | None:
    """Declared core_version against the latest upstream tag and release."""
    repo = named.repo
    if repo is None or not named.declared:
        return None
    release = upstream.latest_release(repo, cache_dir, offline)
    # Asked by name: the first page of tags misses a release that a project
    # publishing nightlies has pushed past a hundred newer tags.
    commit = upstream.tag_commit(repo, named.tag, cache_dir, offline)
    return VersionReport(
        named.declared,
        upstream.newest_tag(repo, cache_dir, offline),
        release.tag if release else None,
        release.date if release else None,
        commit is not None,
        commit,
        named.tag,
        named.distance,
    )


def page_version(
    profile: dict, cache_dir: str, offline: bool
) -> tuple[str | None, str | None]:
    """The latest version a profile's version_source page announces.

    Forty-odd profiles live off any forge: profile_sync could only say
    "unsupported host", and a new Altirra or mednafen release went unseen.
    Returns (version, None) or (None, why the page gave no version): a page
    not cached offline, absent, refused, or one the pattern no longer finds.
    One None for all four read like a profile with no version_source.
    """
    source = profile.get("version_source") or {}
    url, pattern = str(source.get("url") or ""), str(source.get("pattern") or "")
    if not url or not pattern:
        return None, "version_source names no url or pattern"
    try:
        text = upstream.fetch_page(url, cache_dir, offline)
    except upstream.NotCachedError:
        return None, "not cached offline"
    except upstream.UpstreamError as exc:
        return None, f"{url}: {exc}"
    if text is None:
        return None, "page absent"
    match = re.search(pattern, text)
    return (match.group(1), None) if match else (None, "pattern not found")


def page_declared(profile: dict, announced: str | None) -> str | None:
    """The core_version a version_source page is held against.

    A core_version keyed by build mode states one version per build, and the
    page announces one of them (eduke32's synthesis page, its standalone).
    The build the page names is the one compared, else the first declared.
    """
    value = profile.get("core_version")
    modes = [str(mode) for mode in value] if isinstance(value, dict) else [""]
    stated = [version for mode in modes if (version := declared(profile, mode))]
    if announced in stated:
        return announced
    return stated[0] if stated else None


def version_warning(
    report: VersionReport | None,
    pin: str | None,
    relation: tuple[int, int] | None = None,
    passed_release: str | None = None,
) -> str | None:
    """Flag a declared version that names a tag away from the resolved pin.

    ``relation`` is the pin's (ahead, behind) count against the tag commit.
    A pin after its tag is a build between two releases. A pin before it
    describes code the declared release had already replaced.
    ``passed_release`` is a later release the pin already contains, which
    core_version should name instead.
    """
    if report is None or not pin:
        return None
    # Before the tag guard: parallel-launcher declared 9.0.5, a name no tag
    # carries (v9.0-6), and the release its HEAD contains went unsaid.
    if passed_release:
        return (
            f"core_version {report.declared} is older than the code: the pin "
            f"{pin[:7]} already contains release {passed_release}"
        )
    if not report.tag_commit or report.tag_commit == pin:
        return None
    if report.distance and relation == (report.distance, 0):
        # The distance core_version states: the build it says it is.
        return None
    where = ""
    if relation is not None:
        ahead, behind = relation
        if ahead and not behind:
            where = f", {ahead} commits after the tag"
        elif behind and not ahead:
            where = f", {behind} commits before the tag: core_version is later than the code"
        elif ahead and behind:
            where = f", off the tag's history ({ahead} ahead, {behind} behind)"
    return (
        f"core_version {report.declared} names tag commit {report.tag_commit[:7]}, "
        f"the pin resolved to {pin[:7]}{where}"
    )


# A tag that reads as a version number: 1.1, v107, v9.0-6, 2.55, 1.1d.
# Nightly, continuous and latest tags do not.
_VERSION_TAG_RE = re.compile(r"v?\d+(?:[._-]\d+)*[a-z]?", re.IGNORECASE)


def published_version(version: VersionReport | None) -> str | None:
    """The latest version the project published: its latest release, or for
    a project that publishes no release, its newest tag when that tag reads
    as a version number.

    GitLab and Codeberg projects often tag without a release: eightyone sat
    on v1.2 and higan on 106 while v1.3 and v107 were tagged, and nothing
    compared them.
    """
    if version is None:
        return None
    if version.latest_release:
        return version.latest_release
    tag = version.latest_tag
    if tag and _VERSION_TAG_RE.fullmatch(tag):
        return tag
    return None


def _later_number(candidate: str, declared: str) -> bool:
    """Whether both read as numbers of one scheme and the candidate's is higher.

    One scheme means the same major number: libretro forks tag RetroArch's
    numbers (mame2015 0.160 beside v1.4.1) and some projects tag dates
    (np2pi 0.83 beside 20120302). Trailing zeros do not count: v1 is v1.0.
    """
    if not (_VERSION_TAG_RE.fullmatch(candidate) and _VERSION_TAG_RE.fullmatch(declared)):
        return False

    def key(text: str) -> tuple[int, ...]:
        numbers = [int(n) for n in re.findall(r"\d+", text)]
        while len(numbers) > 1 and numbers[-1] == 0:
            numbers.pop()
        return tuple(numbers)

    high, low = key(candidate), key(declared)
    if (len(high) == 1) != (len(low) == 1):
        return False
    if len(high) == 1:
        # higan 106 and v107 are one scheme, openlara v1 and 20170424 two.
        return len(str(high[0])) == len(str(low[0])) and high > low
    return high[0] == low[0] and high > low


def newer_release(
    repo: upstream.Repo,
    version: VersionReport | None,
    pin: str | None,
    cache_dir: str,
    offline: bool,
) -> str | None:
    """The latest release, when it comes after both the declared tag and the pin.

    A profile pinned on its release tag reads as clean forever: armsx1 sat on
    0.1.3, armsx2 on 2.8 and x1-box on 1.2.6 while 0.3.6, 2.9 and 1.3.2 were
    out, and nothing said so. A held pin (pin_frozen) is left alone.
    """
    published = published_version(version)
    if not version or not pin or not version.tag_commit or not published:
        return None
    if published == version.named:
        return None
    commit = upstream.tag_commit(repo, published, cache_dir, offline)
    if not commit or commit == pin:
        return None
    after_tag = upstream.ancestry(repo, version.tag_commit, commit, cache_dir, offline)
    if not after_tag or after_tag[0] == 0 or after_tag[1] != 0:
        return None
    after_pin = upstream.ancestry(repo, pin, commit, cache_dir, offline)
    if not after_pin or after_pin[0] == 0:
        return None
    return published


def latest_passed_release(
    repo: upstream.Repo,
    version: VersionReport | None,
    pin: str | None,
    cache_dir: str,
    offline: bool,
) -> str | None:
    """The latest release, when the pin already contains it and core_version
    names another one.

    The latest tag is no witness: nightly, continuous and Pre-release tags
    sort first on many forges. The latest release is a version the project
    published as such.
    """
    published = published_version(version)
    if not version or not pin or not published:
        return None
    if published == version.named:
        return None
    if not version.tag_commit and not _later_number(published, version.named):
        # No tag to order them: only a release numbered past the declared
        # version says it is older. "latest", "continuous" or 1.53 under a
        # declared 1.61 say nothing.
        return None
    commit = upstream.tag_commit(repo, published, cache_dir, offline)
    if not commit:
        return None
    if version.tag_commit and version.tag_commit != commit:
        # A project can publish a release older than its newest tag:
        # pcsx2x6's latest release is v0.2.20, its declared tag v0.2.22.
        older = upstream.ancestry(repo, commit, version.tag_commit, cache_dir, offline)
        if older and older[1] == 0:
            return None
    if commit == pin:
        return published
    relation = upstream.ancestry(repo, commit, pin, cache_dir, offline)
    if relation and relation[1] == 0:
        return published
    return None
