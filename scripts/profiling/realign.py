"""Prose citations written under an older pin, moved to the pin the profile carries now."""

from __future__ import annotations

import itertools
import posixpath
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from core import upstream
from model.sourceref import RefPart
from profiling.anchoring import anchor_block
from profiling.attribution import owner_order
from profiling.citations import Citation, citation_key, collect_citations, is_external_citation
from profiling.proseedit import apply_prose_edits, run_after_moves
from model.profilerepos import declared_repositories
from profiling.yamledit import apply_edit


def _git_history(path: Path) -> list[str] | None:
    """Commits touching the profile, newest first, or None when git cannot say.

    An untracked profile has no history. A git that fails (no repository,
    dubious ownership, git missing) has not answered, and reading that as
    "nothing written under an older pin" let a bump through.
    """
    def git(*argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *argv], cwd=path.parent, capture_output=True, text=True, check=False,
        )

    try:
        result = git("log", "--format=%H", "--", path.name)
        deleted = git("log", "--format=%H", "--diff-filter=D", "--", path.name)
        if result.returncode == 0 and deleted.returncode == 0:
            # A commit that deletes or renames the file away ends the history
            # of the profile now at that path: what precedes it is another
            # profile once filed under the same name (mupen64plus.yml became
            # mupen64plus_next.yml before the standalone took the name).
            history = result.stdout.split()
            ends = set(deleted.stdout.split())
            cut = next((i for i, sha in enumerate(history) if sha in ends), len(history))
            return history[:cut]
        # A repository with no commit yet holds nothing written earlier.
        inside = git("rev-parse", "--is-inside-work-tree")
        if inside.stdout.strip() == "true" and git("rev-parse", "-q", "--verify", "HEAD").returncode:
            return []
    except OSError:
        pass
    return None


def _git_file_at(path: Path, sha: str) -> dict | None:
    """The profile as it was at one commit, None when unreadable."""
    result = subprocess.run(
        ["git", "show", f"{sha}:./{path.name}"],
        cwd=path.parent, capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return None
    try:
        document = yaml.safe_load(result.stdout)
    except yaml.YAMLError:
        return None
    return document if isinstance(document, dict) else None


def _pin_of(
    document: dict, field: str, mode: str = "",
    repo: upstream.Repo | None = None,
) -> str | None:
    """A pin as the profile records it, read for one build mode when keyed.

    With `repo`, a pin the document declares for another repository under
    the field and mode does not count. A past revision can pin another
    repository under the same field: xenia-edge's source_commit named the
    has207/xenia-edge sha until the field became a dict keyed by mode, and
    read for the libretro mode that old string passed for a pin of the
    GitLab port that moved under unchanged prose.
    """
    value = document.get(field)
    if isinstance(value, dict):
        value = value.get(mode) if mode else None
    if not (isinstance(value, str) and value):
        return None
    if repo is not None:
        url_field = field.removesuffix("_commit")
        declared = {
            (mode_key, url)
            for name, mode_key, url in declared_repositories(document)
            if name == url_field
        }
        url = next(
            (u for m, u in declared if m == mode),
            next((u for m, u in declared if not m), None),
        )
        owner = upstream.parse_repo(url) if url else None
        if owner is not None and (owner.host, owner.slug.lower()) != (
            repo.host, repo.slug.lower()
        ):
            return None
    return value


def _writing_pins(
    revisions: list[tuple[str, dict]], intro_sha: str, field: str, mode: str = "",
    repo: upstream.Repo | None = None,
) -> list[str]:
    """Distinct pins committed while the scalar held its current text.

    The pin at the introducing commit stands for the scalars that predate
    it (the backfill resolved missing pins from profiled_date). A pin that
    moved later under the same text is either a bump that left the prose
    behind or a correction putting the pin on the revision the text already
    described: vitaquake2 was written under 34f0888, then re-pinned to
    59a5115 by a commit that touched nothing else. The history cannot tell
    the two apart, so every pin the text lived under is returned.
    """
    index = next(
        (i for i, (sha, _) in enumerate(revisions) if sha == intro_sha), None
    )
    if index is None:
        return []
    pins: list[str] = []
    for position in range(index, -1, -1):
        value = _pin_of(revisions[position][1], field, mode, repo)
        if value and value not in pins:
            pins.append(value)
    return pins


def _resolve_at(
    repo: upstream.Repo, sha: str, path: str, cache_dir: str, offline: bool
) -> tuple[str, tuple[str, list[str]] | str | None]:
    """("found", (path, lines)) or ("unclear"|"missing", reason).

    Prose often cites a bare filename. The tree at the revision resolves it
    when exactly one path carries that name. An unreadable or truncated
    tree, or several paths carrying the name, proves nothing: those come
    back "unclear", never "missing", because a verdict of absence taken on
    a tree that could not be read would rot the citation with confidence.
    """
    candidates = [path]
    head, _, tail = path.partition("/")
    if tail and head == repo.name:
        candidates.append(tail)
    for candidate in candidates:
        lines = upstream.fetch_file(repo, sha, candidate, cache_dir, offline)
        if lines is not None:
            return "found", (candidate, lines)
    if "/" not in path:
        tree, truncated = upstream.list_tree(repo, sha, cache_dir, offline)
        matches = [p for p in tree or [] if posixpath.basename(p) == path]
        if len(matches) == 1:
            lines = upstream.fetch_file(
                repo, sha, matches[0], cache_dir, offline
            )
            if lines is not None:
                return "found", (matches[0], lines)
        elif len(matches) > 1:
            return "unclear", f"{len(matches)} paths carry the name"
        elif truncated or not tree:
            return "unclear", "tree unreadable at that revision"
    return "missing", None


def _realign_part(
    part: RefPart,
    pairs: list[tuple[upstream.Repo, str, str]],
    cache_dir: str,
    offline: bool,
    pinned: Iterable[tuple[upstream.Repo, str]] = (),
    declared: Mapping[upstream.Repo, tuple[str, str]] | None = None,
) -> tuple[str, tuple[int, int] | str] | None:
    """One range, anchored from its writing revision to the current pin.

    `pinned` lists every declared (repository, current pin). A path no moved
    repository carries but an unmoved one does lives where nothing moved:
    it needs no move, and calling it absent made two readings of the same
    history disagree on every run (nethersx2's AetherSX2 citations).
    `declared` gives the (field, build mode) of each repository, which the
    part's role word is matched against.
    """
    if is_external_citation(part.path):
        return None
    # The role word decides first, as attribution does: retrodream cites
    # `(upstream retro_host.c:196-198)` beside the fork's retro_host.c, and
    # both trees carry the file.
    fields = declared or {}

    def claim(item: tuple) -> tuple[str, str]:
        return fields.get(item[0], ("source", ""))

    pairs = owner_order(pairs, part.role, claim)
    pinned = owner_order(pinned, part.role, claim)
    # Then the path as written, as attribution reads it: a prefix is
    # stripped only when no declared repository carries the path itself.
    # hatarib's hatari/src/tos.c lives in hatariB, which did not move, and
    # stripping the prefix read it as hatari/hatari's src/tos.c instead.
    # Between two repositories that both carry the path, owner_order puts
    # first the one declared first: freej2me-plus and hex007/freej2me both
    # hold src/libretro/, and the citations describe the fork.
    literal = [
        (repo, written, current) for repo, written, current in pairs
        if upstream.fetch_file(repo, written, part.path, cache_dir, offline) is not None
    ]
    moved = {repo for repo, _written, _current in pairs}
    order = [repo for repo, _pin in pinned]
    first_moved = min(
        (order.index(repo) for repo, _w, _c in literal if repo in order),
        default=len(order),
    )
    if any(
        upstream.fetch_file(repo, pin, part.path, cache_dir, offline) is not None
        for index, (repo, pin) in enumerate(pinned)
        if repo not in moved and (not literal or index < first_moved)
    ):
        return None
    unclear: tuple[str, list[str]] | str | None = None
    for repo, written, current in literal or pairs:
        state, payload = _resolve_at(repo, written, part.path, cache_dir, offline)
        if state == "unclear":
            unclear = payload
            continue
        if not isinstance(payload, tuple):
            continue
        actual, old_lines = payload
        new_lines = upstream.fetch_file(
            repo, current, actual, cache_dir, offline
        )
        if new_lines is None:
            return "skip", f"{part.path} absent at the current pin"
        anchored = anchor_block(
            old_lines, new_lines, part.start, part.end or part.start
        )
        if anchored.status == "ANCHORED":
            return None
        if anchored.status == "SHIFTED" and anchored.start is not None and anchored.end is not None:
            return "ok", (anchored.start, anchored.end)
        return "skip", f"{part.path}:{part.start} {anchored.status.lower()}"
    if unclear:
        return "skip", f"{part.path}: {unclear}"
    if any(
        upstream.fetch_file(repo, pin, part.path, cache_dir, offline) is not None
        for repo, pin in pinned
        if repo not in moved
    ):
        return None
    return "skip", f"{part.path} absent at the writing revision"


def _writing_pairs(
    document: dict, repos: list, revisions: list[tuple[str, dict]], intro_sha: str,
    served: dict | None = None,
) -> tuple[list[list], list[str]]:
    """Every reading of where the text was written, and the ambiguities.

    Each reading lists (repo, writing pin, current pin) per declared
    repository. A repository whose text lived under several pins gives one
    reading per pin, and the caller settles them when they all agree.

    `prose_written_at` names the pin a reader confirmed the prose against.
    Among several candidate pins it is the answer: fixnes's doOpenFDSBIOS
    citation lived under four pins, exact at the last, and with nothing to
    record that reading the bump stayed refused for good. It never
    overrides a history with a single candidate.
    """
    options: list[list] = []
    ambiguous: list[str] = []
    attested = str(document.get("prose_written_at") or "")
    for pin_field, mode, repo in repos:
        current = _pin_of(document, f"{pin_field}_commit", mode)
        if not current:
            continue
        written = _writing_pins(
            revisions, intro_sha, f"{pin_field}_commit", mode, repo
        )
        if attested in written:
            written = [attested]
        if len(written) > 1:
            ambiguous.append(f"{pin_field}_commit {' -> '.join(written)}")
        # The current pin among the candidates reads as "no move" (None) for
        # that repository, which the other candidates must then agree with.
        reader = (served or {}).get(repo, repo)
        options.append([
            (reader, pin, current) if pin != current else None for pin in written
        ])
    readings = [
        [pair for pair in combo if pair is not None]
        for combo in itertools.product(*options)
    ]
    return readings, ambiguous


def _realign_citation(
    citation: Citation,
    readings: list[list],
    ambiguous: list[str],
    cache_dir: str,
    offline: bool,
    pinned: Iterable[tuple[upstream.Repo, str]] = (),
    declared: Mapping[upstream.Repo, tuple[str, str]] | None = None,
) -> tuple[dict[int, tuple[int, int, str | None]], list[str]]:
    """The moves one prose run needs, and what blocks them.

    Several pins under one text: the history cannot say which the text
    describes, but when the cited range lands in the same place from every
    one of them the question does not matter. When the readings disagree,
    moving from the wrong one rewrites a correct citation onto someone
    else's code, with nothing to show it happened.
    """
    moves: dict[int, tuple[int, int, str | None]] = {}
    blocked: list[str] = []
    for index, part in enumerate(citation.parts):
        outcomes = {
            repr(result): result
            for result in (
                _realign_part(part, pairs, cache_dir, offline, pinned, declared) if pairs else None
                for pairs in readings
            )
        }
        if len(outcomes) > 1:
            blocked.extend(
                f"pin moved under this text: {item}; the readings disagree"
                for item in ambiguous
            )
            continue
        outcome = next(iter(outcomes.values()))
        if outcome is None:
            continue
        _state, payload = outcome
        if isinstance(payload, tuple):
            moves[index] = (payload[0], payload[1], None)
        else:
            blocked.append(payload)
    return moves, blocked


@dataclass(frozen=True)
class _ProseRepos:
    """The repositories prose is read in, as realign_prose reads them."""

    # (pin field, build mode, repository) for each declared repository.
    repos: list[tuple[str, str, upstream.Repo]]
    # A source declared gone, read through its mirror.
    served: dict[upstream.Repo, upstream.Repo]
    # Every declared (repository, current pin).
    pinned: list[tuple[upstream.Repo, str]]
    # The (field, build mode) each repository read is declared under.
    roles: dict[upstream.Repo, tuple[str, str]]


def _prose_repos(document: dict) -> _ProseRepos | None:
    """The repositories the profile's prose is read in, None when it declares none."""
    # Every repository the profile declares, by build mode where it keys
    # them so: eka2l1, mesence, supermodel and xemu pin a dict, and reading
    # str(dict) found no repository at all, so their prose was never judged.
    repos = [
        (field, mode, repo)
        for field, mode, url in declared_repositories(document)
        if field != "source_mirror" and (repo := upstream.parse_repo(url)) is not None
    ]
    if not repos:
        return None
    # A source declared gone is read through its mirror, which carries the
    # same commits: teknoparrot's notes stayed blocked once
    # teknogods/TeknoParrotUI answered 404, every reading of the old pin
    # calling the files absent.
    mirror = (
        upstream.parse_repo(str(document.get("source_mirror") or ""))
        if document.get("upstream_gone") else None
    )
    served = {
        repo: mirror for field, _mode, repo in repos
        if mirror is not None and field == "source"
    }
    pinned = [
        (served.get(repo, repo), pin)
        for field, mode, repo in repos
        if (pin := _pin_of(document, f"{field}_commit", mode))
    ]
    roles = {served.get(repo, repo): (field, mode) for field, mode, repo in repos}
    return _ProseRepos(repos, served, pinned, roles)


@dataclass
class _ProseHistory:
    """Where each prose citation came into the profile's history."""

    # The commit that introduced each citation's text, None when uncommitted.
    intro: list[str | None]
    revisions: list[tuple[str, dict]] = field(default_factory=list)
    # Citations whose writing pin lies past a revision that cannot be read:
    # where their text came in is unknown, so they are not moved.
    unknown: dict[int, str] = field(default_factory=dict)


def _carried_by(past: dict) -> set[tuple[str, str]]:
    return {
        (c.field, citation_key(c.ref))
        for c in collect_citations(past) if c.kind == "prose"
    }


def _date_prose(
    path: Path, document: dict, keys: list[tuple[str, str]], history: list[str]
) -> _ProseHistory:
    """Follow each citation back through the commits that carry its text."""
    alive = [True] * len(keys)
    found = _ProseHistory([None] * len(keys))
    # A revision that does not parse is passed over unless the pins differ
    # on its two sides while the citation is absent across it: then the
    # text may have come in there under either pin. Otherwise nothing
    # it could hold changes the reading. lindbergh-loader
    # committed invalid YAML once (df7346b3), fixed the same day, and every
    # note older than that commit stayed blocked for good.
    gap: str | None = None
    for sha in history:
        if not any(alive):
            break
        past = _git_file_at(path, sha)
        if past is None:
            gap = gap or sha
            continue
        held = _carried_by(past)
        if gap:
            newer = found.revisions[-1][1] if found.revisions else document
            moved = any(
                newer.get(pin) != past.get(pin)
                for pin in ("source_commit", "upstream_commit")
            )
            for index, live in enumerate(alive):
                if live and moved and keys[index] not in held:
                    found.unknown[index] = gap
                    alive[index] = False
            gap = None
        found.revisions.append((sha, past))
        for index, live in enumerate(alive):
            if not live:
                continue
            if keys[index] in held:
                found.intro[index] = sha
            else:
                alive[index] = False
    if gap:
        # The oldest revisions do not parse: where the text came in is past
        # what can be read.
        found.unknown.update({index: gap for index, live in enumerate(alive) if live})
    return found


def _prose_jobs(
    document: dict,
    citations: list[Citation],
    dated: _ProseHistory,
    declared: _ProseRepos,
    cache_dir: str,
    offline: bool,
) -> tuple[list[str], list[tuple[Citation, dict]]]:
    """The moves each dated citation needs, and the messages on the others."""
    messages: list[str] = []
    jobs: list[tuple[Citation, dict]] = []
    for index, citation in enumerate(citations):
        if index in dated.unknown:
            messages.append(
                f"read again: {citation.field}: {citation.ref} "
                f"(revision {dated.unknown[index][:8]} unreadable)"
            )
            continue
        intro_sha = dated.intro[index]
        if intro_sha is None:
            # The scalar is not committed yet: written now, under this pin.
            continue
        readings, ambiguous = _writing_pairs(
            document, declared.repos, dated.revisions, intro_sha, declared.served
        )
        if not any(readings):
            continue
        moves, blocked = _realign_citation(
            citation, readings, ambiguous, cache_dir, offline, declared.pinned,
            declared.roles,
        )
        if blocked:
            # Half a run must not move: the untouched ranges would read as
            # already realigned when they were never even located.
            messages.extend(
                f"read again: {citation.field}: {citation.ref} ({reason})"
                for reason in blocked
            )
            continue
        if moves:
            jobs.append((citation, moves))
    return messages, jobs


def realign_prose(
    path: Path, cache_dir: str, offline: bool = False, dry_run: bool = False
) -> list[str]:
    """Recale prose runs from the pin their text was written at.

    A prose run written under an older pin describes that revision, and
    anchoring it from the current pin would faithfully track the wrong
    content: the cited line holds someone else's code there. The writing pin
    is read from the profile's own history, at the commit that introduced
    the scalar's current text, and only when no other pin was committed
    under that text since.
    """
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        return []
    citations = [c for c in collect_citations(document) if c.kind == "prose"]
    if not citations:
        return []
    declared = _prose_repos(document)
    if declared is None:
        return []
    history = _git_history(path)
    if history is None:
        return [f"read again: {path.name}: git history unreadable"]
    if not history:
        return []

    # Each citation is followed on its own: a field's text changes whenever
    # one of its citations is corrected by hand, and dating the whole field
    # from that commit put idtech4a++'s untouched Game.java:69-72 under the
    # current pin, so the stale range was never offered again.
    keys = [(c.field, citation_key(c.ref)) for c in citations]
    dated = _date_prose(path, document, keys, history)
    messages, jobs = _prose_jobs(document, citations, dated, declared, cache_dir, offline)

    if dry_run:
        messages.extend(
            f"would recale {citation.field}: {citation.ref} -> "
            f"{run_after_moves(citation.parts, moves, citation.ref)}"
            for citation, moves in jobs
        )
        return messages
    new_text, applied, left = apply_prose_edits(text, jobs, document)
    messages.extend(applied)
    messages.extend(f"left in place: {item}" for item in left)
    if applied:
        apply_edit(path, new_text, document)
    return messages
