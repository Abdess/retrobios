"""What a profile report starts from: the refs it anchors, the repositories it reads, the revisions it compares."""

from __future__ import annotations

import posixpath
from collections.abc import Callable, Iterable
from dataclasses import replace

from core import forgehttp, upstream, upstreamtree
from model.profilerepos import declared_repositories
from model.sourceref import RefPart, ref_role, resolve_project_word, split_source_ref
from profiling.citations import (
    Citation,
    anchor_tokens,
    collect_citations,
    entry_hashes,
    is_external_citation,
    strip_repo_word,
)
from profiling.reports import ProfileReport, SkipKind
from profiling.repos import (
    RepoView,
    build_revision,
    detect_pinned_tag,
    moved_repositories,
    reads_own_revision,
    resolve_through_gitlinks,
    select_repo,
    select_views,
    shipped_build_holders,
    tag_pinned_views,
)


def resolve_project_words(
    refs: list, tree_order: Callable[[], Iterable[list[str] | None]],
    link_order: Callable[[], Iterable[Iterable[str]]] = lambda: (),
) -> list:
    """Point `project file` parts at the declared tree that vendors them.

    tree_order() yields the trees to search, pin before HEAD, and
    link_order() the submodule paths of the declared trees at their pins.
    Each is only called for a part that needs it, since reading a tree costs
    a request. Parts no tree carries stay external.
    """
    resolved: dict[str, str | None] = {}
    out = []
    for display, ref, tokens, hashes, parts, citation in refs:
        rewritten = []
        for part in parts:
            if is_external_citation(part.path):
                if part.path not in resolved:
                    resolved[part.path] = resolve_project_word(
                        part.path, tree_order()
                    ) or resolve_through_gitlinks(part.path, link_order())
                if resolved[part.path]:
                    part = replace(part, path=resolved[part.path])
            rewritten.append(part)
        out.append((display, ref, tokens, hashes, rewritten, citation))
    return out


def cited_path_roles(refs: list) -> dict[str, set[str]]:
    """The roles each cited path is written under across the profile."""
    roles: dict[str, set[str]] = {}
    for *_, parts, _citation in refs:
        for part in parts:
            if part.role:
                roles.setdefault(part.path, set()).add(part.role)
    return roles


def check_build_refs(
    profile: dict,
    deferred: list[tuple[Citation, dict]],
    views: list[RepoView],
    fetch: Callable[[upstream.Repo, str, str], list[str] | None],
) -> list[dict]:
    """Each deferred config_reads ref read at the build of its platforms.

    The file must exist at that revision and every cited line lie inside
    it. The entry declares no value to anchor on, so this is the check a
    ref past the end of its file fails (BUILD_GONE), not a content match.
    """
    results: list[dict] = []
    for citation, read in deferred:
        for platform in read.get("platforms") or []:
            # A closed build is named by its binary: an address ref is
            # skipped below, a source path cannot exist at a sha256.
            revision = (str(read.get("revision") or read.get("binary_sha256") or "")
                        or build_revision(profile, str(platform)))
            row = {"platform": str(platform), "revision": revision or "",
                   "ref": citation.ref, "field": citation.field}
            if revision is None:
                results.append({**row, "status": "BUILD_UNREAD",
                                "detail": "no pin_build revision for this platform"})
                continue
            problems: list[str] = []
            for part in split_source_ref(citation.ref):
                role, path = ref_role(part.path)
                if " " in path:
                    # A project word in front (`ROCKNIX patches/x.patch:4`):
                    # a file of the platform's tree, read with the record.
                    continue
                lines = next(
                    (found for view in views
                     if (not role or view.field == role)
                     and (found := fetch(view.repo, revision, path)) is not None),
                    None,
                )
                if lines is None:
                    problems.append(f"{part.path} absent at {revision[:12]}")
                elif (part.end or part.start or 0) > len(lines):
                    problems.append(f"{part.raw} past the end ({len(lines)} lines)")
            results.append({
                **row,
                "status": "BUILD_GONE" if problems else "BUILD_OK",
                "detail": "; ".join(problems),
            })
    return results


def gather_refs(
    profile: dict, text: str | None
) -> tuple[list, list[tuple[Citation, dict]]]:
    """The citations to anchor, and the refs read at a shipped build instead.

    One citation surface for the whole document. A prose citation carries
    no declared value, so it anchors on content alone: the nudge and
    relocation heuristics stay off rather than guess from a profile-wide
    token pool.
    """
    known = frozenset(
        repo.name.lower()
        for _, _, url in declared_repositories(profile)
        if (repo := upstream.parse_repo(url)) is not None
    )
    modes = {mode for _, mode, _ in declared_repositories(profile) if mode}
    refs = []
    at_build = shipped_build_holders(profile)
    deferred: list[tuple[Citation, dict]] = []
    for citation in collect_citations(profile, text):
        if citation.kind == "ref" and id(citation.holder) in at_build:
            # Written for the build a platform ships: read at pin_build.
            deferred.append((citation, at_build[id(citation.holder)]))
            continue
        if citation.kind == "ref":
            entry = citation.entry or {}
            display = str(entry.get("name") or "") or citation.field
            if citation.label:
                display += f" [{citation.label}]"
            # The repository a part says its lines are in (`upstream
            # src/a.c:5`) stays on that part: the same path can be cited
            # under both roles in one profile.
            # An entry of one build mode reads that build's repository when
            # the profile keys its source by mode.
            mode = str(citation.label or entry.get("mode") or "")
            mode = mode if mode in modes else ""
            parts = [
                RefPart(
                    strip_repo_word(p.path, known), p.start, p.end, p.raw,
                    ref_role(p.path)[0] or mode,
                )
                for p in split_source_ref(citation.ref)
            ]
            refs.append((
                display, citation.ref, anchor_tokens(entry),
                entry_hashes(entry), parts, citation,
            ))
        else:
            refs.append((
                citation.field, citation.ref, [], [],
                list(citation.parts), citation,
            ))
    return refs, deferred


def cited_directories(refs: list) -> set[str]:
    """Directories the profile already cites, deepest first, to settle a bare
    filename that several trees of one repository carry."""
    cited_dirs: set[str] = set()
    for _, _, _, _, parts, _ in refs:
        for part in parts:
            directory = posixpath.dirname(part.path)
            while directory:
                cited_dirs.add(directory)
                directory = posixpath.dirname(directory)
    return cited_dirs


def _unanswered_skip(profile: dict) -> str:
    """Why a profile no declared repository answers for is skipped."""
    # A declared pin whose repository or branch does not answer is not a
    # profile without a pin: pyxel's kitao/pyxel answers 404, and the
    # message sent the reader looking for a missing source_commit.
    return (
        "no declared repository answers (moved, removed, or a branch the "
        "forge does not know)"
        if profile.get("source_commit") or profile.get("upstream_commit")
        else "no source_commit and no resolvable profiled_date "
        "on any declared repository"
    )


def readable_views(
    profile: dict, report: ProfileReport, cache_dir: str, offline: bool
) -> list[RepoView] | None:
    """The repositories to read, None once the report says why it is skipped."""
    report.unread = [
        url
        for _, _, url in declared_repositories(profile)
        if upstream.parse_repo(url) is None
    ]
    if select_repo(profile) is None:
        declared = str(profile.get("source") or profile.get("upstream") or "")
        report.skip(
            SkipKind.UNSUPPORTED_HOST, f"unsupported host: {declared or 'none declared'}"
        )
        return None

    stated_gone = str(profile.get("upstream_gone") or "").strip()

    try:
        views = select_views(profile, cache_dir, offline)
    except forgehttp.RateLimitError:
        raise
    except forgehttp.UpstreamError:
        # citron's dead domain now resolves to an unrelated host that fails
        # TLS: for a forge the profile declares gone, any refusal agrees.
        if stated_gone:
            # The profile says the forge is gone and the forge agrees. That is
            # a recorded fact, not an open problem: the refs describe the last
            # revision anyone can reach, and nothing further is possible.
            report.skip(SkipKind.GONE_DECLARED, f"upstream gone (declared): {stated_gone}")
            return None
        raise
    if stated_gone and any(view.field != "source_mirror" for view in views):
        # Declared dead, yet it answered. A profile that keeps saying so stops
        # being read, so the contradiction is the finding.
        report.skip(
            SkipKind.GONE_CONTRADICTED,
            f"upstream_gone is declared but the forge answers: {stated_gone}",
        )
        return None
    if not views and stated_gone:
        report.skip(SkipKind.GONE_DECLARED, f"upstream gone (declared): {stated_gone}")
        return None
    if not views:
        report.skip(SkipKind.UNANSWERED, _unanswered_skip(profile))
        return None
    return views


def record_revisions(
    profile: dict, report: ProfileReport, views: list[RepoView],
    cache_dir: str, offline: bool,
) -> dict[tuple[str, str], str]:
    """Put the revisions under comparison on the report, and return the views
    read at their release tag."""
    primary = views[0]
    report.repo, report.host = primary.repo.slug, primary.repo.host
    report.repos = [v.repo.slug for v in views]
    report.pin, report.pin_origin = primary.pin, primary.origin
    report.head = primary.head
    for view in views[1:]:
        if view.field == "upstream":
            report.upstream_pin = view.pin
            report.upstream_head = view.head
            report.upstream_origin = view.origin
    report.moved_repos = moved_repositories(views, cache_dir, offline)
    # A profile can hold its pin on purpose, documenting a build that is that
    # revision. Comparing it to HEAD says nothing and recaling would repoint
    # its refs at code the build never had, so it is judged like a frozen tag:
    # against itself.
    frozen = str(profile.get("pin_frozen") or "").strip()
    report.pin_frozen = bool(frozen)
    report.pinned_tag = frozen or detect_pinned_tag(
        profile, views, cache_dir, offline
    )
    # A repository pinned on its release tag is read at that tag, whichever
    # role it plays: comparing mame0174 refs with mamedev HEAD says nothing.
    tagged = tag_pinned_views(profile, views, cache_dir, offline)
    report.upstream_tag = next(
        (
            tagged[(view.repo.host, view.repo.slug)]
            for view in views
            if view.field == "upstream" and (view.repo.host, view.repo.slug) in tagged
        ),
        None,
    )

    if not report.pinned_tag:
        # A tag or a held pin is off the tracked branch by design.
        report.orphaned = [
            f"{view.repo.slug}: pin {view.pin[:8]} is no ancestor of {view.head[:8]}"
            for view in views
            if not reads_own_revision(view, tagged)
            and upstreamtree.compare(
                view.repo, view.pin, view.head, cache_dir, offline
            ).diverged
        ]
    return tagged
