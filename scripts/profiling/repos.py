"""The repositories a profile declares and the revision each one is read at."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace

from core import upstream


PIN = "pin"
HEAD = "head"


@dataclass(frozen=True)
class RepoView:
    """One repository a profile cites, at the two revisions under comparison."""

    repo: upstream.Repo
    pin: str
    head: str
    origin: str
    field: str
    # The build mode a keyed source names this repository under (ymir,
    # xenia-edge): `standalone` or `libretro`, empty for a plain URL.
    mode: str = ""


def select_repo(profile: dict) -> upstream.Repo | None:
    """Repository the profile was read from: source first, then upstream.

    A source keyed by build mode with no upstream (uzdoom) names its
    repositories only in the dict, which a plain string read never parses.
    """
    for field_name in ("source", "upstream"):
        repo = upstream.parse_repo(str(profile.get(field_name) or ""))
        if repo is not None:
            return repo
    for _, _, url in declared_repositories(profile):
        repo = upstream.parse_repo(url)
        if repo is not None:
            return repo
    return None


def resolve_pin(
    profile: dict, repo: upstream.Repo, cache_dir: str, offline: bool,
    field: str = "source", mode: str = "", branch: str | None = None,
) -> tuple[str, str] | tuple[None, None]:
    """Commit the profile was written at, and how it was obtained.

    `field` selects which declared pin applies: `source_commit` for the port
    the profile was read from, `upstream_commit` for the original project.
    A profile whose builds live in different repositories keys its pin by
    build mode, the way `ymir` keys `source` and `core_version`.
    """
    pinned = profile.get(f"{field}_commit")
    if isinstance(pinned, dict):
        pinned = pinned.get(mode)
        origin = f"{field}_commit[{mode}]"
    else:
        origin = f"{field}_commit"
    if pinned:
        return str(pinned), origin
    date = str(profile.get("profiled_date") or "")
    if not date:
        return None, None
    sha = upstream.resolve_commit_at(repo, date, cache_dir, offline, branch)
    return (sha, f"profiled_date {date}") if sha else (None, None)


def select_views(
    profile: dict, cache_dir: str, offline: bool
) -> list[RepoView]:
    """Every repository the profile cites, source before upstream.

    241 profiles declare a `source` distinct from their `upstream`, and 168 of
    those have both on a supported forge. Their refs mix paths from the two, so
    a single repository cannot resolve them all.
    """
    views: list[RepoView] = []
    seen: set[tuple[str, str]] = set()
    gone = False
    # A port living on a branch of a fork is absent from the default tip, so
    # the branch it was read from is followed when the profile names one.
    declared = str(profile.get("source_branch") or "") or None
    for field_name, mode, url in declared_repositories(profile):
        repo = upstream.parse_repo(url)
        if repo is None or (repo.host, repo.slug) in seen:
            continue
        # A mirror carries the source's history, commits and branches alike:
        # its pin is source_commit. It read `source_mirror_commit`, a field
        # no profile carries, and fell back to profiled_date, which a bump
        # never moves (eden judged from f6e76860 while pinned on d16735f5).
        pin_field = "source" if field_name == "source_mirror" else field_name
        branch = declared if pin_field == "source" else None
        head = None
        try:
            unread: upstream.NotCachedError | None = None
            for candidate in branch_candidates(url):
                try:
                    head = upstream.resolve_head(repo, cache_dir, offline, candidate)
                except upstream.NotCachedError as exc:
                    # Another prefix of the /tree/ tail may be the cached branch.
                    unread = exc
                    continue
                if head:
                    branch = candidate
                    break
            if unread and not head:
                raise unread
            pin, origin = resolve_pin(
                profile, repo, cache_dir, offline, pin_field, mode, branch
            )
            if not pin or origin is None:
                continue
            head = head or upstream.resolve_head(repo, cache_dir, offline, branch)
        except upstream.GoneError:
            # yuzu's source answers 451: the mirror declared after it is what
            # keeps the profile checkable, so a gone repository is passed over.
            gone = True
            continue
        if not head:
            continue
        if head != pin and not offline:
            # A tip cached before the pin was written is older than the pin:
            # scummvm-standalone pinned 6f7b060d while the cache still held
            # 77d80d7, and a bump would have moved the pin backwards.
            relation = upstream.ancestry(repo, pin, head, cache_dir, offline)
            if relation and relation[0] == 0 and relation[1] > 0:
                head = upstream.resolve_head(repo, cache_dir, offline, branch, fresh=True) or head
        seen.add((repo.host, repo.slug))
        views.append(RepoView(repo, pin, head, origin, field_name, mode))
    if gone and not views:
        raise upstream.GoneError(f"{profile.get('emulator', '?')}: every declared repository is gone")
    views = _follow_fork_base(_follow_submodule(views, cache_dir, offline), cache_dir, offline)
    return _hold_upstream(profile, views)


def _hold_upstream(profile: dict, views: list[RepoView]) -> list[RepoView]:
    """An upstream tree the port vendors or synced to is judged at that
    revision: aps3e carries RPCS3 1f080485, yaps2 PCSX2 342db515."""
    if not str(profile.get("upstream_frozen") or "").strip():
        return views
    return [
        replace(view, head=view.pin, origin=f"{view.origin}, held")
        if view.field == "upstream" else view
        for view in views
    ]


def _follow_submodule(
    views: list[RepoView], cache_dir: str, offline: bool
) -> list[RepoView]:
    """An upstream the port vendors as a submodule moves with the port.

    libretro/TIC-80 builds nesbox/TIC-80 through its `core` submodule, and
    upstream_commit was that submodule's commit. Compared to nesbox's own
    HEAD, the view reported changes the shipped core never had, and a bump
    would have moved upstream_commit past what it builds. The commit the
    port's HEAD points the submodule at is the upstream HEAD that matters.
    """
    source = next((v for v in views if v.field == "source"), None)
    behind = [v for v in views if v.field == "upstream" and v.pin != v.head]
    if source is None or not behind:
        return views
    pinned = {
        sha: path
        for path, sha in upstream.list_gitlinks(
            source.repo, source.pin, cache_dir, offline
        ).items()
    }
    if not pinned:
        return views
    followed: list[RepoView] = []
    for view in views:
        path = pinned.get(view.pin) if view.field == "upstream" else None
        head = (
            upstream.list_gitlinks(source.repo, source.head, cache_dir, offline).get(path)
            if path else None
        )
        followed.append(
            replace(view, head=head, origin=f"{view.origin} via {path}")
            if head else view
        )
    return followed


def _follow_fork_base(
    views: list[RepoView], cache_dir: str, offline: bool
) -> list[RepoView]:
    """An upstream the port is a fork of moves with what the port merged.

    snes9x, kronos, np2kai and six others pinned upstream_commit on the merge
    base of upstream with the fork, the upstream code the port carries. Read
    against upstream's own HEAD, the bump moved it past anything the port
    built from. Outside one fork network the HEAD stays the reference.
    """
    source = next((v for v in views if v.field == "source"), None)
    if source is None:
        return views
    followed: list[RepoView] = []
    for view in views:
        if view.field != "upstream" or view.pin == view.head or " via " in view.origin:
            followed.append(view)
            continue
        base = upstream.fork_base(
            view.repo, view.head, source.repo, source.head, cache_dir, offline
        )
        if base and base != view.pin:
            # A pin newer than the merge base names code the port does not
            # carry: the upstream is a build of its own, the Qt melonDS or the
            # EasyRPG Player a standalone + libretro profile documents, and
            # its HEAD stays the reference. melonds read 825 commits back.
            moved = upstream.ancestry(view.repo, base, view.pin, cache_dir, offline)
            if moved and moved[0] > 0 and moved[1] == 0:
                base = None
        followed.append(
            replace(view, head=base, origin=f"{view.origin}, fork base of {source.repo.slug}")
            if base else view
        )
    return followed


def declared_repositories(profile: dict) -> list[tuple[str, str, str]]:
    """Every repository URL the profile declares, source before upstream.

    `source` and `upstream` are usually plain strings. `ymir` keys them by
    build mode instead, because its standalone and libretro builds live in
    different repositories.

    `source_mirror` comes last and is the only thing that keeps a profile
    checkable once its forge is gone: yuzu and suyu answer 451, citron's
    host stopped resolving. Being last, it never decides attribution while
    a declared repository still answers.
    """
    urls: list[tuple[str, str, str]] = []
    for field_name in ("source", "upstream", "source_mirror"):
        value = profile.get(field_name)
        if isinstance(value, dict):
            urls.extend((field_name, str(k), str(v)) for k, v in value.items() if v)
        elif value:
            urls.append((field_name, "", str(value)))
    return urls


def branch_in_url(url: str) -> str | None:
    """Branch named by a forge URL pointing inside a repository.

    A profile can cite a fork as `.../Ymir/tree/libretro`, which names both
    the repository and the branch the port lives on. The tail may go on into
    a directory (`.../libretro-samples/tree/master/tests/cruzes`): this is
    the whole tail, and branch_candidates() its prefixes.
    """
    _, sep, tail = url.partition("/tree/")
    return tail.strip("/") or None if sep else None


def branch_candidates(url: str) -> list[str]:
    """Each prefix of a /tree/ tail, shortest first, that may be the branch.

    A branch name can hold a slash, so the tail is not split blindly. The
    first prefix the forge resolves is the branch, the rest a directory.
    Taken whole, `master/tests/cruzes` resolved to nothing and the profile
    was skipped as having no resolvable pin.
    """
    tail = branch_in_url(url)
    if not tail:
        return []
    parts = tail.split("/")
    return ["/".join(parts[:n]) for n in range(1, len(parts) + 1)]


def version_tag_candidates(core_version: object, repo_name: str = "") -> list[str]:
    """Tag spellings a declared core_version might use.

    Some projects prefix their own name and drop the separators, the way
    mamedev/mame publishes 0.289 as `mame0289`, so that spelling is derived
    from the repository name rather than listed per project.
    """
    version = str(core_version or "").strip()
    if not version or " " in version:
        return []
    bare = version.lstrip("vV")
    spellings = [version, f"v{bare}", bare]
    if repo_name:
        spellings.append(f"{repo_name}{bare.replace('.', '')}")
    return list(dict.fromkeys(spellings))


def detect_pinned_tag(
    profile: dict, views: list[RepoView], cache_dir: str, offline: bool
) -> str | None:
    """Tag the profile is pinned to, when the repository has moved past it.

    A profile can document a frozen release line that lives as a tag inside a
    still-developed repository. HEAD is then a different program: the refs
    describe the tag and must never be recaled onto modern code. `pcsx2-legacy`
    is pinned to v1.6.0 of PCSX2, where a plugin-era DEV9 ref resolves onto the
    modern built-in DEV9, a different code path.

    The declared `core_version` names the tag, which is looked up by name so
    that a repository publishing nightly tags cannot hide an old release behind
    pagination.

    Only the repository of the documented build freezes the profile. An
    `upstream` a port was cut from sits on a release tag as its base
    (GroovyMAME on mame0289, triforce on Dolphin 2407) while the port itself
    keeps moving: that view is judged against its tag by `tag_pinned_views`,
    and the port is still compared with its HEAD and still bumped.
    """
    documented = [view for view in views if view.field != "upstream"] or views
    tagged = tag_pinned_views(profile, documented, cache_dir, offline)
    return next(iter(tagged.values()), None)


def tag_pinned_views(
    profile: dict, views: list[RepoView], cache_dir: str, offline: bool
) -> dict[tuple[str, str], str]:
    """Views whose pin is the tag `core_version` names, keyed by repository.

    A core_version keyed by build mode names the tag of the view's own mode:
    uzdoom's standalone sits on 5.0.3 while its libretro branch moves.
    """
    tagged: dict[tuple[str, str], str] = {}
    declared = profile.get("core_version")
    for view in views:
        if view.pin == view.head:
            continue
        version = declared.get(view.mode) if isinstance(declared, dict) else declared
        for tag in version_tag_candidates(version, view.repo.name):
            if upstream.tag_commit(view.repo, tag, cache_dir, offline) == view.pin:
                tagged[(view.repo.host, view.repo.slug)] = tag
                break
    return tagged


def resolve_through_gitlinks(path: str, links: Iterable[Iterable[str]]) -> str | None:
    """Path of `project file` inside the one submodule named after the project.

    idtech4a++ cites `xash3d-fwgs filesystem/filesystem.c` and starship
    `Torch src/Companion.cpp`: the declared tree holds a gitlink there, not
    the files, so no blob path answers and the part stayed external.
    """
    word, _, rest = path.partition(" ")
    rest = rest.strip().lstrip("/")
    if not rest:
        return None
    word = word.lower()
    for paths in links:
        matches = [
            link for link in paths or ()
            if word in link.rsplit("/", 1)[-1].lower()
        ]
        if len(matches) == 1:
            return f"{matches[0]}/{rest}"
        if matches:
            return None
    return None


def moved_repositories(
    views: list[RepoView], cache_dir: str, offline: bool
) -> list[str]:
    """Declared repositories the forge now answers under another name."""
    moved = []
    seen: set[tuple[str, str]] = set()
    for view in views:
        key = (view.repo.host, view.repo.slug)
        if key in seen:
            continue
        seen.add(key)
        current = upstream.current_slug(view.repo, cache_dir, offline)
        if current and current.lower() != view.repo.slug.lower():
            moved.append(
                f"{view.repo.slug} answers as {current} (renamed or transferred)"
            )
    return moved


def shipped_build_holders(profile: dict) -> dict[int, dict]:
    """The source_ref holders of config_reads entries naming platforms, by id.

    Such an entry describes the build those platforms ship, so its refs are
    read at their pin_build revision, never at source_commit.
    """
    found: dict[int, dict] = {}
    for read in profile.get("config_reads") or []:
        if not isinstance(read, dict) or not read.get("platforms"):
            continue
        found[id(read)] = read
        for key in read.get("keys") or []:
            if isinstance(key, dict):
                found[id(key)] = read
    return found


def build_revision(profile: dict, platform: str) -> str | None:
    """The emulator revision a platform's pin_build entry names, None when
    its value is no revision (a URL, a package name)."""
    for build in profile.get("pin_build") or []:
        if build.get("platform") != platform:
            continue
        value = str(build.get("value") or "").strip()
        return value if value and re.fullmatch(r"[\w.+-]+", value) else None
    return None


def reads_own_revision(view: RepoView, tagged: dict[tuple[str, str], str]) -> bool:
    """Whether a view is read at its own revision: on HEAD, or on its tag."""
    return view.pin == view.head or (view.repo.host, view.repo.slug) in tagged
