"""Read a profile's core_version from the source its version_basis records.

A profile states the version of the code it was read at. Copied from a
libretro .info or left behind by a pin advance, it named another release:
snes9x said 1.61 at a pin whose snes9x.h states 1.63, and four bulk advances
moved 295 pins without touching one version. version_basis records where the
version is read, so a tool can read it again at any pin:

- ``file``: a pattern in one file of a declared repository at its pin, the
  version the program states (a macro, a build file, a package file).
- ``tag``: the nearest tag in the pin's history and the commits after it,
  for code that takes its version from git at build time. core_version is
  the tag at distance 0, else ``<tag>-<distance>-g<pin7>``, git describe's
  form.
- ``alias``: the same binary as another profile, whose version it carries.
- ``package``: an artefact read outside any source tree (an Android package,
  a closed binary, a release archive): a version no pin can be asked for.
  A pattern reads it from the artefact's name when the name states it.
- ``none``: the code at the pin states no version and no tag reaches it.
  core_version is then null.
- ``unverified``: no reading could be made (``why``: no pin, a host the
  tools cannot read, a forge gone, no build named as read, no source).
  core_version stays as written and is reported unconfirmed.

A profile whose builds live in different repositories keys version_basis by
build mode, the way it keys core_version.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from core import upstream
from core import forgehttp
from core import upstreamtree
from model.profilerepos import pin_field
from profiling.repos import resolve_pin, select_repo

KINDS = ("file", "tag", "alias", "package", "none", "unverified")
# Values copied from a .info or a branch name, which name no version.
PLACEHOLDERS = frozenset({"git", "svn", "unknown", "master", "main", "latest", "dev", "head"})

MATCH = "MATCH"
DRIFT = "DRIFT"
UNREADABLE = "UNREADABLE"
NO_BASIS = "NO_BASIS"
UNCHECKED = "UNCHECKED"
FAILING = (DRIFT, UNREADABLE, NO_BASIS)

_FIELD = re.compile(r"\{(\d+)(?::([^}]*))?\}")


class VersionUnreadable(Exception):
    """The basis yields no version at the pin it is asked about."""


@dataclass(frozen=True)
class Reading:
    mode: str
    kind: str
    declared: str | None
    read: str | None
    where: str
    status: str
    # What a write sets beside core_version: the tag and distance of a tag basis.
    updates: tuple[tuple[str, object], ...] = ()


def bases(profile: dict) -> dict[str, dict]:
    """The basis of each build mode, "" when one covers every build."""
    basis = profile.get("version_basis")
    if not isinstance(basis, dict):
        return {}
    if "kind" in basis:
        return {"": basis}
    return {str(mode): value for mode, value in basis.items() if isinstance(value, dict)}


def declared(profile: dict, mode: str) -> str | None:
    """core_version for a build mode, as written."""
    value = profile.get("core_version")
    if isinstance(value, dict):
        value = value.get(mode)
    return None if value is None else str(value)


def _by_mode(profile: dict, field: str, mode: str) -> str | None:
    value = profile.get(field)
    if isinstance(value, dict):
        value = value.get(mode)
    return str(value) if value else None


def version_repo(
    profile: dict, mode: str = "", basis: dict | None = None,
) -> tuple[upstream.Repo | None, str]:
    """The repository core_version describes, and the profile field naming it.

    The basis says where the version is read: its url (field "url"), else
    the repository its `repo` field names. pcee2 reads PCSX2's tags, which
    the port the profile was read from never carries. A profile with no
    basis is read in the repository it was profiled from.
    """
    if basis is None:
        basis = bases(profile).get(mode)
    if not basis:
        return select_repo(profile), "source"
    if basis.get("url"):
        return upstream.parse_repo(str(basis["url"])), "url"
    field = str(basis.get("repo") or "source")
    return upstream.parse_repo(_by_mode(profile, field, mode) or ""), field


@dataclass(frozen=True)
class VersionTag:
    """The tag core_version names for one build mode, and where it lives."""

    mode: str
    declared: str
    tag: str
    distance: int
    repo: upstream.Repo | None
    field: str


def version_tags(profile: dict) -> list[VersionTag]:
    """Which tag core_version names, for each build mode and repository.

    A tag basis holds the tag apart from core_version, which writes git
    describe's long form past it (armsx2 2.9.2-77-gfc4ab0b names tag 2.9.2).
    Any other basis names the tag by core_version itself. Builds naming the
    same tag in the same repository are one answer.
    """
    found = bases(profile)
    value = profile.get("core_version")
    modes = list(found) or ([str(mode) for mode in value] if isinstance(value, dict) else [""])
    answers: list[VersionTag] = []
    seen: set[tuple] = set()
    for mode in modes:
        stated = declared(profile, mode)
        if not stated:
            continue
        basis = found.get(mode)
        tag, distance = stated, 0
        if basis and basis.get("kind") == "tag" and basis.get("tag"):
            tag, distance = str(basis["tag"]), int(basis.get("distance") or 0)
        repo, field = version_repo(profile, mode, basis)
        key = (repo.host, repo.slug) if repo else None, field, stated, tag
        if key in seen:
            continue
        seen.add(key)
        answers.append(VersionTag(mode, stated, tag, distance, repo, field))
    return answers


def is_placeholder(value: object) -> bool:
    """A VCS or branch word standing for a version, alone or annotated
    ("SVN (2015 snapshot)"). The schema refuses the same strings."""
    if not isinstance(value, str):
        return False
    return re.split(r"[\s(]", value.strip(), maxsplit=1)[0].casefold() in PLACEHOLDERS


def format_version(match: re.Match, template: str | None) -> str:
    """The groups of a match laid out by template, `{1}.{2}` or `{4:02d}`.

    A format spec applies to the group read as an integer: FBNeo writes its
    alpha number on two digits (VER_ALPHA 3 is 1.0.0.03).
    """
    if not template:
        return match.group(1).strip()

    def field(found: re.Match) -> str:
        text = match.group(int(found.group(1))) or ""
        spec = found.group(2)
        return format(int(text, 0), spec) if spec else text.strip()

    return _FIELD.sub(field, template)


def read_text_version(text: str, pattern: str, template: str | None) -> tuple[str, int] | None:
    """The version a pattern reads in a file's text, and its line number."""
    found = re.search(pattern, text, re.MULTILINE)
    if not found:
        return None
    return format_version(found, template), text.count("\n", 0, found.start()) + 1


def describe_form(tag: str, distance: int, pin: str) -> str:
    """core_version of a tag basis: the tag, or git describe's long form."""
    return tag if distance == 0 else f"{tag}-{distance}-g{pin[:7]}"


def _repo_and_pin(
    profile: dict, basis: dict, mode: str, cache_dir: str, offline: bool,
) -> tuple[upstream.Repo, str]:
    """The repository a basis reads and the commit it is read at."""
    repo, field = version_repo(profile, mode, basis)
    if field == "url":
        pin = str(basis.get("commit") or "")
        where = str(basis["url"])
    else:
        where = _by_mode(profile, field, mode) or field
        pin = ""
        if repo is not None:
            # The pin profile_sync compares at: the declared commit, else
            # the commit at profiled_date on the branch the source follows.
            pinned_by = pin_field(field)
            branch = str(profile.get("source_branch") or "") or None
            pin = resolve_pin(
                profile, repo, cache_dir, offline, pinned_by, mode,
                branch if pinned_by == "source" else None,
            )[0] or ""
    if repo is None:
        raise VersionUnreadable(f"{where}: not a forge repository")
    if not pin:
        raise VersionUnreadable(f"{repo.slug}: no pinned commit")
    return repo, pin


def _ancestry(
    repo: upstream.Repo, base: str, head: str, cache_dir: str, offline: bool,
) -> tuple[int, int] | None:
    """The forge's compare, else the commit graph: GitHub refuses with 422
    a compare whose diff is too large (aps3e's tag and pin)."""
    try:
        relation = upstreamtree.ancestry(repo, base, head, cache_dir, offline)
    except forgehttp.RateLimitError:
        raise
    except forgehttp.UpstreamError:
        relation = None
    if relation is None:
        try:
            relation = upstreamtree.graph_ancestry(repo, base, head, cache_dir, offline)
        except forgehttp.NotCachedError:
            return None
    return relation


@dataclass(frozen=True)
class _Request:
    """One basis read for one build mode, and what its readings carry."""

    profile: dict
    mode: str
    basis: dict
    kind: str
    stated: str | None
    cache_dir: str
    offline: bool
    profiles: dict | None
    recompute: bool

    def reading(self, value: str | None, where: str, updates: tuple = ()) -> Reading:
        status = MATCH if value == self.stated else DRIFT
        return Reading(self.mode, self.kind, self.stated, value, where, status, updates)

    def unreadable(self, reason: str) -> Reading:
        return Reading(self.mode, self.kind, self.stated, None, reason, UNREADABLE)

    def repo_and_pin(self) -> tuple[upstream.Repo, str]:
        return _repo_and_pin(self.profile, self.basis, self.mode, self.cache_dir, self.offline)


def _read_none(req: _Request) -> Reading:
    if req.recompute:
        # A release tagged since the basis was written gives the
        # code a version: the advance has to name it.
        repo, pin = req.repo_and_pin()
        described = upstreamtree.describe(repo, pin, req.cache_dir, req.offline)
        if described is not None:
            tag, distance = described
            return Reading(req.mode, req.kind, req.stated, describe_form(tag, distance, pin),
                           f"{repo.slug}: tag {tag} is now in "
                           f"{pin[:7]}'s history", DRIFT)
    return req.reading(None, "the code states no version")


def _read_unverified(req: _Request) -> Reading:
    return Reading(req.mode, req.kind, req.stated, None, f"not verified: {req.basis.get('why')}",
                   UNCHECKED)


def _read_package(req: _Request) -> Reading:
    artifact = str(req.basis.get("artifact") or "")
    if req.basis.get("pattern"):
        # An artefact named after its version says it in its name:
        # advancemame-0.94.0.tar.gz.
        found = read_text_version(artifact, str(req.basis["pattern"]), req.basis.get("format"))
        if found is None:
            return req.unreadable(f"{artifact}: pattern not found")
        return req.reading(found[0], f"named by {artifact}")
    return Reading(req.mode, req.kind, req.stated, None, f"read from {artifact}", UNCHECKED)


def _read_alias(req: _Request) -> Reading:
    other = (req.profiles or {}).get(str(req.basis.get("of") or ""))
    if other is None:
        return req.unreadable(f"alias of {req.basis.get('of')}: no such profile")
    return req.reading(declared(other, req.mode) if isinstance(other.get("core_version"), dict)
                       else declared(other, ""), f"alias of {req.basis['of']}")


def _read_file(req: _Request, repo: upstream.Repo, pin: str) -> Reading:
    path = str(req.basis.get("path") or "")
    lines = upstream.fetch_file(repo, pin, path, req.cache_dir, req.offline)
    if lines is None:
        return req.unreadable(f"{repo.slug}@{pin[:7]}:{path}: absent")
    found = read_text_version("\n".join(lines), str(req.basis.get("pattern") or ""),
                              req.basis.get("format"))
    if found is None:
        return req.unreadable(f"{repo.slug}@{pin[:7]}:{path}: pattern not found")
    value, line = found
    return req.reading(value, f"{repo.slug}@{pin[:7]}:{path}:{line}")


def _read_tag(req: _Request, repo: upstream.Repo, pin: str) -> Reading:
    basis = req.basis
    if req.recompute:
        described = upstreamtree.describe(repo, pin, req.cache_dir, req.offline, basis.get("match"))
        if described is None:
            return req.unreadable(f"{repo.slug}@{pin[:7]}: no tag in its history")
        tag, distance = described
    else:
        tag, distance = str(basis.get("tag") or ""), basis.get("distance")
        commit = upstream.tag_commit(repo, tag, req.cache_dir, req.offline)
        if commit is None:
            return req.unreadable(f"{repo.slug}: no tag {tag}")
        relation = (0, 0) if commit == pin else _ancestry(
            repo, commit, pin, req.cache_dir, req.offline)
        if relation is None:
            return req.unreadable(f"{repo.slug}: {tag}...{pin[:7]} not comparable")
        if relation[1]:
            return req.unreadable(f"{repo.slug}: tag {tag} is not in {pin[:7]}'s history")
        if relation[0] != distance:
            return Reading(req.mode, req.kind, req.stated, describe_form(tag, relation[0], pin),
                           f"{repo.slug}: {pin[:7]} is {relation[0]} commits after "
                           f"{tag}, the basis says {distance}", DRIFT,
                           (("distance", relation[0]),))
    return req.reading(describe_form(tag, distance, pin),
                       f"{repo.slug}: tag {tag} + {distance}",
                       (("tag", tag), ("distance", distance)))


_OFF_FORGE: dict[str, Callable[[_Request], Reading]] = {
    "none": _read_none,
    "unverified": _read_unverified,
    "package": _read_package,
    "alias": _read_alias,
}
_ON_FORGE: dict[str, Callable[[_Request, upstream.Repo, str], Reading]] = {
    "file": _read_file,
    "tag": _read_tag,
}


def read(
    profile: dict, mode: str, basis: dict, cache_dir: str, offline: bool,
    profiles: dict | None = None, recompute: bool = False,
) -> Reading:
    """The version the basis yields at the profile's pin, against core_version.

    ``recompute`` asks git for the nearest tag again, the way a pin advance
    has to: a recorded tag only proves its own distance, and a tag released
    between the two pins would go unseen.
    """
    kind = str(basis.get("kind") or "")
    req = _Request(profile, mode, basis, kind, declared(profile, mode),
                   cache_dir, offline, profiles, recompute)
    try:
        off_forge = _OFF_FORGE.get(kind)
        if off_forge is not None:
            return off_forge(req)
        repo, pin = req.repo_and_pin()
        on_forge = _ON_FORGE.get(kind)
        if on_forge is not None:
            return on_forge(req, repo, pin)
    except (forgehttp.UpstreamError, VersionUnreadable) as exc:
        return req.unreadable(str(exc))
    return req.unreadable(f"unknown kind {kind!r}")


def check(
    profile: dict, cache_dir: str, offline: bool, profiles: dict | None = None,
    recompute: bool = False,
) -> list[Reading]:
    """One reading per build mode, or a NO_BASIS reading."""
    found = bases(profile)
    if not found:
        return [Reading("", "", declared(profile, ""), None, "no version_basis", NO_BASIS)]
    return [read(profile, mode, basis, cache_dir, offline, profiles, recompute)
            for mode, basis in found.items()]
