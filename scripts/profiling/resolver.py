"""Builds a profile's report: each citation resolved against its repositories at the pin and at HEAD."""

from __future__ import annotations

import functools
import itertools
import posixpath
import re
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace

from core import upstream
from core.upstream import CompareResult
from model.sourceref import RefPart, ref_role, resolve_project_word, split_source_ref
from profiling.anchoring import (
    BLANK_LOOKAHEAD,
    PartResult,
    STATUS_ORDER,
    TREE_TRUNCATED,
    anchor_part,
    dominant_shifts,
    reconcile_self_check,
    refuse_collapsing_moves,
    resolve_by_shift,
    resolve_rename,
    verify_at_pin,
    worst_status,
)
from profiling.citations import (
    Citation,
    anchor_tokens,
    cites_another_version,
    collect_citations,
    entry_hashes,
    is_external_citation,
    narrow_by_cited,
    strip_repo_word,
    symlink_target,
)
from profiling.reports import EntryReport, ProfileReport
from profiling.repos import (
    PIN,
    RepoView,
    reads_own_revision,
    build_revision,
    declared_repositories,
    detect_pinned_tag,
    moved_repositories,
    resolve_through_gitlinks,
    select_repo,
    select_views,
    shipped_build_holders,
    tag_pinned_views,
)


def _resolve_project_words(
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


def _path_roles(refs: list) -> dict[str, set[str]]:
    """The roles each cited path is written under across the profile."""
    roles: dict[str, set[str]] = {}
    for *_, parts, _citation in refs:
        for part in parts:
            if part.role:
                roles.setdefault(part.path, set()).add(part.role)
    return roles


def _check_build_refs(
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


def _gather_refs(
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


def _cited_dirs(refs: list) -> set[str]:
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


def _readable_views(
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
        report.skipped = f"unsupported host: {declared or 'none declared'}"
        return None

    stated_gone = str(profile.get("upstream_gone") or "").strip()

    try:
        views = select_views(profile, cache_dir, offline)
    except upstream.RateLimitError:
        raise
    except upstream.UpstreamError:
        # citron's dead domain now resolves to an unrelated host that fails
        # TLS: for a forge the profile declares gone, any refusal agrees.
        if stated_gone:
            # The profile says the forge is gone and the forge agrees. That is
            # a recorded fact, not an open problem: the refs describe the last
            # revision anyone can reach, and nothing further is possible.
            report.skipped = f"upstream gone (declared): {stated_gone}"
            return None
        raise
    if stated_gone and any(view.field != "source_mirror" for view in views):
        # Declared dead, yet it answered. A profile that keeps saying so stops
        # being read, so the contradiction is the finding.
        report.skipped = (
            f"upstream_gone is declared but the forge answers: {stated_gone}"
        )
        return None
    if not views and stated_gone:
        report.skipped = f"upstream gone (declared): {stated_gone}"
        return None
    if not views:
        report.skipped = _unanswered_skip(profile)
        return None
    return views


def _record_revisions(
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
            and upstream.compare(
                view.repo, view.pin, view.head, cache_dir, offline
            ).diverged
        ]
    return tagged


def _line_score(lines: list[str], start: int | None, tokens: tuple) -> int:
    """How well a repository's cited line matches what the ref means.

    Two repositories can hold the same path with different contents:
    `mame` cites files that both mamedev/mame and its libretro fork
    carry, and the fork's tree is offset, so its line 5545 is a real
    but unrelated statement. A line carrying the entry's own subject
    beats a merely non-empty one, which in turn beats a blank.
    """
    if start is None:
        return 2
    if start > len(lines):
        return 0
    # A blank cited line opens the block below it: lrps2's
    # VMManager.cpp:418 is blank in the fork it was written for, and
    # scored 0 it handed the ref to the upstream, where 418 is
    # unrelated code that then decided the rebase target.
    line = next(
        (ln.lower() for ln in lines[start - 1:start - 1 + BLANK_LOOKAHEAD]
         if ln.strip()),
        "",
    )
    # A set name sits between delimiters in a MAME declaration, so
    # `pgm` matches `GAME( 1997, pgm,` but not `pgm_012_025_drgw2`,
    # which is what tells the two repositories apart.
    if tokens and any(
        re.search(rf"\b{re.escape(tok)}\b", line) for tok in tokens
    ):
        return 3
    if tokens and any(tok in line for tok in tokens):
        return 2
    return 1 if line.strip() else 0


@dataclass
class _Resolver:
    """Where each cited path lives across the declared repositories, and how
    a part reads there, memoised for one profile."""

    name: str
    profile: dict
    cache_dir: str
    offline: bool
    views: list[RepoView]
    report: ProfileReport
    tagged: dict[tuple[str, str], str]
    # A part that names no repository is looked up first where its path is
    # cited elsewhere: a note citing `src/a.c:12` beside source_refs that
    # all read `upstream src/a.c` means that tree.
    # A path cited under both roles lends neither, and such a part is
    # compared in every repository rather than in whichever comes first.
    path_roles: dict[str, set[str]]
    cited_dirs: set[str]
    owners: dict[tuple[str, int | None, tuple, str], tuple[RepoView, str]] = field(
        default_factory=dict
    )
    context: dict[str, tuple[CompareResult, list[str]]] = field(default_factory=dict)
    truncated_trees: set[str] = field(default_factory=set)
    pin_trees: dict[str, list[str]] = field(default_factory=dict)
    mute: set[tuple[str, str]] = field(default_factory=set)
    lines_cache: dict[
        tuple[str, str, int | None, tuple[str, ...], str | None, str], list[str]
    ] = field(default_factory=dict)

    @property
    def primary(self) -> RepoView:
        return self.views[0]

    def role_of(self, part: RefPart) -> str:
        if part.role:
            return part.role
        lent = self.path_roles.get(part.path, ())
        return next(iter(lent)) if len(lent) == 1 else ""

    def on_own_revision(self, view: RepoView) -> bool:
        return reads_own_revision(view, self.tagged)

    def trees_in_order(self) -> Iterable[list[str] | None]:
        """Pin trees before HEAD trees, each read only when reached."""
        return itertools.chain(
            map(self.pin_tree_for, self.views),
            (self.context_for(v)[1] for v in self.views),
        )

    def gitlinks_in_order(self) -> Iterator[Iterable[str]]:
        """Submodule paths of each declared tree at its pin. A tree the
        forge lists in part is said once and searched as far as it is
        known: the parts it cannot place stay external, as before."""
        for view in self.views:
            try:
                yield upstream.list_gitlinks(view.repo, view.pin, self.cache_dir, self.offline)
            except upstream.TruncatedListingError as exc:
                print(f"{self.name}: submodule paths unknown, {exc}", file=sys.stderr)
                yield ()

    def _add_bare_name_matches(self, path: str, candidates: list[str]) -> None:
        # A bare filename, the way prose cites files. Resolved against the
        # pin before HEAD: the ref was written at the pin, and a file that
        # moved since would otherwise be resolved to a HEAD path that does
        # not exist at the pin, reporting GONE for the one reason it never
        # should. The rename search then carries the pin path to HEAD.
        for view in self.views:
            for tree in (self.pin_tree_for(view), self.context_for(view)[1]):
                matches = [
                    p for p in tree or []
                    if posixpath.basename(p) == path
                ]
                if len(matches) > 1:
                    matches = narrow_by_cited(matches, self.cited_dirs)
                # A few survivors are told apart by the cited line below: a
                # 266-line Windows configure.ac cannot carry line 754.
                if len(matches) <= 4:
                    candidates.extend(
                        m for m in matches if m not in candidates
                    )
                if matches:
                    break

    def _add_suffix_matches(self, path: str, candidates: list[str]) -> None:
        # A path written from a subproject directory of a monorepo:
        # `src/main/Main.cc` in emu-ex-plus-alpha is PCE.emu/src/main/Main.cc
        # for one profile and C64.emu/src/main/Main.cc for another. The
        # tree is searched by suffix and the cited directories decide.
        suffix = "/" + path
        for view in self.views:
            _, tree = self.context_for(view)
            matches = [p for p in tree or [] if p.endswith(suffix)]
            if len(matches) > 1:
                matches = narrow_by_cited(matches, self.cited_dirs)
            if len(matches) <= 4:
                candidates.extend(m for m in matches if m not in candidates)

    def _candidate_paths(self, path: str) -> list[str]:
        """The paths a cited path may stand for, as written first."""
        candidates = [path]
        head, _, tail = path.partition("/")
        if tail and any(head == v.repo.name for v in self.views):
            candidates.append(tail)
        if "/" not in path:
            self._add_bare_name_matches(path, candidates)
        elif not any(
            self.fetch_from(v.repo, sha, path) is not None
            for v in self.views for sha in (v.pin, v.head)
        ):
            self._add_suffix_matches(path, candidates)
        return candidates

    def _upstream_on_line(
        self, candidate: str, at_pin: bool, start: int | None, tokens: tuple
    ) -> RepoView | None:
        """The upstream holding the entry's value on the cited line too."""
        for other in self.views:
            if _view_role(other) != "upstream":
                continue
            sha = other.pin if at_pin else other.head
            theirs = self.fetch_from(other.repo, sha, candidate)
            if theirs is not None and _line_score(theirs, start, tokens) == 3:
                return other
        return None

    def _try_candidate(
        self,
        candidate: str,
        ordered: list[RepoView],
        start: int | None,
        tokens: tuple,
        wanted: str,
        best: tuple[int, RepoView, str] | None,
    ) -> tuple[tuple[RepoView, str] | None, tuple[int, RepoView, str] | None]:
        """The owner one candidate path settles, else the best seen so far."""
        for at_pin in (True, False):
            for view in ordered:
                sha = view.pin if at_pin else view.head
                found = self.fetch_from(view.repo, sha, candidate)
                if found is None:
                    continue
                target = symlink_target(candidate, found)
                if target:
                    found = self.fetch_from(view.repo, sha, target)
                    if found is None:
                        continue
                    candidate = target
                rank = _line_score(found, start, tokens)
                if rank and _answers(view, wanted) and view.mode:
                    # An entry of one build mode is that build's code:
                    # xenia-edge's standalone xbox.xex refs scored higher
                    # in the libretro tree, whose same file is offset.
                    return (view, candidate), best
                if rank == 3 and not wanted and _view_role(view) == "source":
                    # The port carries a copy of the emulator: when the
                    # original holds the same value on the cited line,
                    # the code asking for the file is the emulator's.
                    other = self._upstream_on_line(candidate, at_pin, start, tokens)
                    if other is not None:
                        return (other, candidate), best
                if rank == 3:
                    return (view, candidate), best
                if best is None or rank > best[0]:
                    best = (rank, view, candidate)
        return None, best

    def locate(
        self, path: str, start: int | None = None, tokens: tuple = (), wanted: str = ""
    ) -> tuple[RepoView, str]:
        """Repository and real path carrying a cited path, HEAD before pin.

        A ref may prefix the path with the repository directory name, as it
        appears in a parent folder holding both clones: 270 parts across 21
        profiles do. That prefix is stripped only as a last resort, once the
        path as written has failed against every repository and revision.

        The pin comes before HEAD because that is the revision the ref was
        written against. `mame` cites files that both mamedev/mame and the
        libretro fork carry today, but only the upstream pin holds them. The
        fork's pin is an older tree where they lived elsewhere.
        """
        candidates = self._candidate_paths(path)
        # A part that names its repository is looked up there first. In a
        # profile keyed by build mode, a part naming none belongs to the
        # first build declared, as _realign_part decides a shared path: the
        # libretro tree of xenia-edge carries emulator.cc offset, and its
        # better-scored line hid a standalone ref that had moved.
        if not wanted and self.primary.mode:
            wanted = self.primary.mode
        ordered = (
            sorted(self.views, key=lambda v: not _answers(v, wanted)) if wanted
            else self.views
        )
        best: tuple[int, RepoView, str] | None = None
        for candidate in candidates:
            found, best = self._try_candidate(candidate, ordered, start, tokens, wanted, best)
            if found is not None:
                return found
        return (best[1], best[2]) if best else (self.primary, path)

    def resolve_path(
        self, path: str, start: int | None = None, tokens: tuple = (), role: str = ""
    ) -> tuple[RepoView, str]:
        key = (path, start, tokens, role)
        if key not in self.owners:
            self.owners[key] = self.locate(path, start, tokens, role)
        return self.owners[key]

    def pin_tree_for(self, view: RepoView) -> list[str]:
        """Tree at the revision the refs were written against, memoised."""
        key = view.repo.slug
        if key not in self.pin_trees:
            tree, _ = upstream.list_tree(view.repo, view.pin, self.cache_dir, self.offline)
            self.pin_trees[key] = tree
        return self.pin_trees[key]

    def fetch_from(self, repo: upstream.Repo, sha: str, wanted: str) -> list[str] | None:
        """Read a file, treating a repository that refuses as one that lacks it.

        A profile can name several repositories, and a mirror exists exactly
        because one of them stopped answering: git.eden-emu.dev returns 403 to
        anything that is not a browser. Letting the first refusal abort the
        report leaves the mirror unread and the profile unverifiable, so the
        repository is muted for the rest of the pass instead. A quota signal
        still ends the profile, and upstream stops asking that host, because
        continuing would only burn the rest of the budget on the same wall.
        """
        # Keyed by host as well as slug: a mirror carries the same slug on
        # another forge, and muting one must not silence the other.
        key = (repo.host, repo.slug)
        if key in self.mute:
            return None
        try:
            found = upstream.fetch_file(repo, sha, wanted, self.cache_dir, self.offline)
            if found is None and "/" in wanted:
                # A file of a submodule is read at the commit its gitlink
                # pins in this revision, so a bump moves it with the port.
                try:
                    inner = upstream.through_gitlink(
                        repo, sha, wanted, self.cache_dir, self.offline
                    )
                except upstream.TruncatedListingError as exc:
                    # The tree is listed in part: the path may sit in a
                    # submodule nobody can see, which is no reason to mute
                    # every other file of the repository.
                    print(f"{self.name}: {wanted} not followed into a submodule, {exc}",
                          file=sys.stderr)
                    inner = None
                if inner is not None:
                    found = upstream.fetch_file(*inner, self.cache_dir, self.offline)
            return found
        except (upstream.RateLimitError, upstream.NotCachedError):
            raise
        except upstream.UpstreamError as exc:
            self.mute.add(key)
            print(f"{self.name}: {repo.host}/{repo.slug} muted, {exc}", file=sys.stderr)
            return None

    def context_for(self, view: RepoView) -> tuple[CompareResult, list[str]]:
        key = view.repo.slug
        if key not in self.context:
            comparison = upstream.compare(
                view.repo, view.pin, view.head, self.cache_dir, self.offline
            )
            tree, truncated = upstream.list_tree(
                view.repo, view.head, self.cache_dir, self.offline
            )
            self.context[key] = (comparison, tree)
            if truncated:
                self.truncated_trees.add(key)
            if truncated and tree:
                print(
                    f"{self.name}: {key} HEAD tree truncated by the forge, "
                    "rename search is partial",
                    file=sys.stderr,
                )
        return self.context[key]

    def rename_getter(self, path: str, role: str = "") -> tuple[str | None, list[str]]:
        """Resolved only when a cited file has vanished, then memoised.

        Every declared repository is searched, not just the one that owns the
        path: a profile citing both a port and its upstream may point at a file
        that only the other one carries.
        """
        owner, actual = self.resolve_path(path, role=role)
        ordered = [owner] + [v for v in self.views if v is not owner]
        candidates: list[str] = []
        for view in ordered:
            comparison, tree = self.context_for(view)
            found, near = resolve_rename(comparison, actual, tree)
            if found:
                return found, []
            # Only the owning repository reports near misses: pooling them
            # across repositories turns a resolvable path into an ambiguous one.
            if view is owner:
                candidates = near
        if not candidates and any(v.repo.slug in self.truncated_trees for v in ordered):
            return None, [TREE_TRUNCATED]
        return None, candidates

    def fetch(
        self,
        which: str,
        path: str,
        start: int | None = None,
        tokens: Iterable[str] = (),
        forced: RepoView | None = None,
        role: str = "",
    ) -> list[str] | None:
        """Lines for one path at one revision, read once per run.

        The same object is handed back every time so the opcode cache can key
        on identity.
        """
        tokens = tuple(tokens)
        key = (which, path, start, tokens, forced.repo.slug if forced else None, role)
        if key not in self.lines_cache:
            view, actual = (
                (forced, path) if forced
                else self.resolve_path(path, start, tokens, role)
            )
            sha = view.pin if which == PIN else view.head
            found = self.fetch_from(view.repo, sha, actual)
            if found is None:
                # Not cached: the miss may be a repository that has just been
                # muted, and the next call resolves the path to a mirror that
                # does carry it. upstream.fetch_file holds its own cache, so
                # asking again costs a lookup rather than a request.
                return None
            self.lines_cache[key] = found
        return self.lines_cache[key]

    def describe(
        self,
        path: str,
        start: int | None = None,
        tokens: Iterable[str] = (),
        forced: RepoView | None = None,
        role: str = "",
    ) -> tuple[str | None, str, str]:
        view, actual = (
            (forced, path) if forced
            else self.resolve_path(path, start, tuple(tokens), role)
        )
        slug = view.repo.slug if view is not self.primary else None
        return slug, upstream.raw_url(view.repo, view.head, actual), actual

    def anchor_across_views(self, part: RefPart, tokens: Sequence[str]) -> PartResult:
        """Judge a part against every repository that carries its path.

        A ref is only broken when it fails everywhere. `mame` cites files that
        both mamedev/mame and its libretro fork hold, with the same delimited
        token on the cited line, so no single attribution can be right for all
        of them. Taking the best outcome across repositories settles it.
        A part that names its repository is judged there alone when that
        repository carries the path: hypseus-singe cites lair.cpp under
        `source` for one entry and `upstream` for the next.
        """
        role = self.role_of(part)
        owner, _actual = self.resolve_path(part.path, part.start, tuple(tokens), role)
        carrying = [
            view for view in self.views
            if self.fetch_from(view.repo, view.pin, part.path) is not None
        ]
        # Judged in the build it belongs to: the best outcome across the
        # builds of a keyed profile let the libretro tree vouch for a
        # standalone ref that had moved (xenia-edge's emulator.cc).
        meant = part.role or self.primary.mode
        named = [view for view in carrying if _answers(view, meant)]
        if meant and named:
            carrying = named
        live = {
            id(view) for view in carrying
            if self.fetch_from(view.repo, view.head, part.path) is not None
        }
        renames = functools.partial(self.rename_getter, role=role)
        best: tuple[int, PartResult] | None = None
        for view in carrying:
            result = anchor_part(
                part,
                functools.partial(self.fetch, forced=view),
                renames,
                functools.partial(self.describe, forced=view),
                tokens,
            )
            if (
                live and id(view) not in live
                and result.status in ("AMBIGUOUS", "GONE")
            ):
                # dosbox-pure's upstream was emptied: its rename search
                # offered the .info, .sln and .vcxproj as candidates and hid
                # the real change in the port that still carries the file.
                continue
            rank = STATUS_ORDER.index(result.status)
            # On a tie the repository the citation is attributed to speaks:
            # mame's "written against HEAD, pin names an older revision" was
            # replaced by whatever the first repository said.
            if best is None or rank < best[0] or (rank == best[0] and view is owner):
                best = (rank, result)
        return best[1] if best else anchor_part(
            part,
            functools.partial(self.fetch, role=role),
            renames,
            functools.partial(self.describe, role=role),
            tokens,
        )

    def self_checked(self, part: RefPart, tokens: Sequence[str]) -> bool:
        """Whether a part is judged on self-consistency rather than compared.

        Comparing a revision with itself anchors every ref whatever it cites,
        so a part whose repository already sits on HEAD is judged on
        self-consistency instead. Decided per part, by the repository that
        owns it: a primary on HEAD says nothing about an upstream that moved on.
        """
        if self.report.pinned_tag:
            return True
        if not part.role and len(self.path_roles.get(part.path, ())) > 1:
            return all(self.on_own_revision(view) for view in self.views)
        view, _ = self.resolve_path(part.path, part.start, tuple(tokens), self.role_of(part))
        return self.on_own_revision(view)

    def _elsewhere_at_own_revision(
        self, part: RefPart, owner: RepoView, tokens: Sequence[str], hashes: Sequence[str],
    ) -> PartResult | None:
        """The verdict of another repository read at its own revision."""
        for view in self.views:
            if view is owner or not self.on_own_revision(view):
                continue
            lines = self.fetch_from(view.repo, view.pin, part.path)
            if lines is None:
                continue
            found = verify_at_pin(part, lines, tokens, hashes)
            if found.status != "GONE":
                return replace(
                    found,
                    repo=None if view is self.primary else view.repo.slug,
                )
        return None

    def _judge_at_pin(
        self, part: RefPart, tokens: Sequence[str], hashes: Sequence[str]
    ) -> PartResult:
        role = self.role_of(part)
        result = verify_at_pin(
            part,
            self.fetch(PIN, part.path, part.start, tokens, role=role),
            tokens, hashes,
        )
        # Checked at its own revision, the part still lies in one tree:
        # the report names it, as a comparison does.
        owner, _actual = self.resolve_path(part.path, part.start, tuple(tokens), role)
        if result.repo is None and owner is not self.primary:
            result = replace(result, repo=owner.repo.slug)
        if result.status == "GONE":
            # The owner is chosen on the cited first line alone. hatari's
            # port carries a longer src/paths.c than the upstream that a
            # source_ref attributes the path to, and prose citing the
            # port's 305-356 read past the end of the upstream's 345
            # lines. As in a comparison, a ref fails only everywhere.
            result = self._elsewhere_at_own_revision(part, owner, tokens, hashes) or result
        return result

    def judge(
        self, part: RefPart, flag: bool, tokens: Sequence[str], hashes: Sequence[str]
    ) -> PartResult:
        other = cites_another_version(part, self.profile.get("core_version"))
        if other:
            # ti99sim cites v0.0.11 beside its v0.16.0 pin: no revision of
            # the pinned repository holds that program, so it cannot anchor.
            return PartResult(
                part, "EXTERNAL", None, None, None, [],
                f"annotated for version {other}, not the documented one",
            )
        if flag:
            result = self._judge_at_pin(part, tokens, hashes)
        else:
            result = self.anchor_across_views(part, tokens)
        # A forge that refused the request said nothing about the file:
        # git.eden-emu.dev answers 403 to scripts, and nine citations of
        # eden-nightly read "absent at HEAD" for a file that exists.
        owner, _actual = self.resolve_path(
            part.path, part.start, tuple(tokens), self.role_of(part)
        )
        if (
            result.status in ("GONE", "AMBIGUOUS")
            and (owner.repo.host, owner.repo.slug) in self.mute
        ):
            return PartResult(
                part, "UNCHECKED", None, None, None, [],
                f"{owner.repo.host}/{owner.repo.slug} refused the request, not read",
            )
        return result


def _judge_refs(resolver: _Resolver, refs: list, report: ProfileReport) -> None:
    """Judge every ref and put its entry on the report."""
    staged = []
    for entry_name, ref, tokens, hashes, ref_parts, citation in refs:
        flags = [resolver.self_checked(part, tokens) for part in ref_parts]
        judged = [
            resolver.judge(part, flag, tokens, hashes)
            for part, flag in zip(ref_parts, flags)
        ]
        staged.append((entry_name, ref, citation, reconcile_self_check(judged, flags)))

    shifts = dominant_shifts([p for _, _, _, parts in staged for p in parts])
    for entry_name, ref, citation, parts in staged:
        parts = refuse_collapsing_moves([resolve_by_shift(p, shifts) for p in parts])
        status = worst_status([p.status for p in parts])
        report.entries.append(EntryReport(
            entry_name, ref, status, parts, citation.kind, citation.field
        ))
        report.counts[status] = report.counts.get(status, 0) + 1


def build_report(
    name: str, profile: dict, cache_dir: str, offline: bool = False,
    text: str | None = None,
) -> ProfileReport:
    """Confront one profile with its upstream."""
    report = ProfileReport(name=name, entries=[], counts={})
    refs, deferred = _gather_refs(profile, text)
    path_roles = _path_roles(refs)
    cited_dirs = _cited_dirs(refs)

    views = _readable_views(profile, report, cache_dir, offline)
    if views is None:
        return report
    tagged = _record_revisions(profile, report, views, cache_dir, offline)

    # A profile carrying no source_ref still has a pin worth writing and a
    # version worth checking, so the revisions above are resolved first.
    if not refs:
        report.skipped = NO_SOURCE_REF
        return report

    resolver = _Resolver(
        name, profile, cache_dir, offline, views, report, tagged, path_roles, cited_dirs
    )
    refs = _resolve_project_words(
        refs, resolver.trees_in_order, resolver.gitlinks_in_order
    )
    report.build_refs = _check_build_refs(profile, deferred, views, resolver.fetch_from)
    _judge_refs(resolver, refs, report)
    return report


def _view_role(view: RepoView) -> str:
    """source or upstream: the profile field a repository comes from."""
    return "upstream" if view.field == "upstream" else "source"


def _answers(view: RepoView, role: str) -> bool:
    """Whether a part written under *role* means this repository: the field
    it comes from, or the build mode a keyed source declares it under."""
    return bool(role) and role in (_view_role(view), view.mode)


NO_SOURCE_REF = "no source_ref"
