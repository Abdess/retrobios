"""Recaling refs and prose citations to HEAD, and what blocks a pin from moving."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from core import upstream
from model.sourceref import ref_role, split_outside_parentheses, split_source_ref
from profiling.anchoring import PartResult, REBASE_STATUSES, REVIEW_STATUSES
from profiling.citations import Citation, citation_key, collect_citations
from profiling.proseedit import apply_prose_edits, run_after_moves, set_scalar
from profiling.reports import EntryReport, ProfileReport, original_part, rendered_part
from profiling.repos import declared_repositories
from profiling.yamledit import YamlWriteError, apply_edit, find_field_line, replace_field_line


def _is_rewritable(ref: str) -> bool:
    """Every ref whose parts can be put back with their prose intact."""
    parts = split_source_ref(ref)
    if not parts:
        return False
    return ", ".join(p.raw for p in parts) == ", ".join(
        chunk for chunk in split_outside_parentheses(ref)
    )


def _match_citation(
    citations: list[Citation], pos: int, entry: EntryReport
) -> tuple[Citation | None, int]:
    """First document citation at or after pos carrying the entry's ref.

    The pairing is by content and order, never by position alone: a
    mode-keyed source_ref yields two report entries for one document line,
    which is exactly the desynchronisation a positional pairing trips on.
    """
    for index in range(pos, len(citations)):
        citation = citations[index]
        if citation.kind != entry.kind or citation.ref != entry.source_ref:
            continue
        if entry.kind == "prose" and entry.field and citation.field != entry.field:
            continue
        return citation, index + 1
    return None, pos


def _prose_moves(
    entry: EntryReport, statuses: tuple[str, ...]
) -> dict[int, tuple[int, int, str | None]]:
    """Recale targets per part of one prose run, empty when unsafe.

    A run cites one file: parts that disagree on where that file went, or a
    rename that would leave untouched ranges pointing into the old file,
    cannot be written without guessing.
    """
    moves: dict[int, tuple[int, int, str | None]] = {}
    renames = set()
    for index, part in enumerate(entry.parts):
        if part.status not in statuses or part.start is None:
            continue
        same_place = (part.start, part.end) == (part.part.start, part.part.end)
        if same_place and not part.new_path:
            continue
        moves[index] = (part.start, part.end or part.start, part.new_path)
        if part.new_path:
            renames.add(part.new_path)
    if len(renames) > 1:
        return {}
    if renames and len(moves) != len(entry.parts):
        return {}
    return moves


def _part_moves(part: PartResult, movable: tuple[str, ...]) -> bool:
    """Whether a part has a new location the recale would write."""
    return (
        part.status in movable
        and part.start is not None
        and ((part.start, part.end) != (part.part.start, part.part.end)
             or bool(part.new_path))
    )


def pin_blockers(report: ProfileReport, accept_changed: bool = False) -> list[str]:
    """What would keep source_commit where it is after a recale, named.

    Two kinds. A ref the writer never regenerates, annotated or under a mode
    key, whose parts have moved. And a prose run whose parts disagree on
    where its file went, which cannot be written without guessing. Either
    one makes bump_commit refuse, so either one has to stop the recale as
    well, and the caller says which.
    """
    movable = REBASE_STATUSES + (("CHANGED",) if accept_changed else ())
    blockers: list[str] = []
    for entry in report.entries or []:
        if entry.kind == "prose":
            if not _prose_moves(entry, movable) and any(
                _part_moves(part, movable) for part in entry.parts
            ):
                blockers.append(
                    f"{entry.field}: {entry.source_ref} "
                    "(its parts do not agree on one new file)"
                )
            continue
        if not any(
            part.status in movable
            and part.start is not None
            and rendered_part(part) != original_part(part)
            for part in entry.parts
        ):
            continue
        if entry.name.endswith("]"):
            blockers.append(
                f"{entry.name}: {entry.source_ref} (under a mode key, moved by hand)"
            )
        elif not _is_rewritable(entry.source_ref):
            blockers.append(
                f"{entry.name}: {entry.source_ref} "
                "(annotated, a rewrite would drop the annotation)"
            )
    return blockers


ATTRIBUTED_STATUSES = ("ANCHORED", "SHIFTED", "RENAMED", "MOVED", "CHANGED")


def attribute_refs(path: Path, report: ProfileReport, profile: dict) -> list[str]:
    """Open each cited path with the role of the repository its lines are in.

    A profile reading a libretro port and the original emulator cited both
    trees the same way, and a reader could not tell whether the core or the
    emulator asked for the file. The role is the one this comparison found
    the lines in, so a word already written that disagrees is corrected.
    Parts whose lines were found nowhere keep what they have.
    """
    if len(report.repos) < 2:
        return []
    role_of: dict[str, str] = {}
    for field_name, _mode, url in declared_repositories(profile):
        repo = upstream.parse_repo(url)
        if repo is not None:
            role_of.setdefault(repo.slug, "source" if field_name == "source_mirror"
                               else field_name)
    if len(set(role_of.values())) < 2:
        return []
    primary = role_of.get(report.repos[0], "source")
    text = path.read_text(encoding="utf-8")
    applied: list[str] = []
    cursor = 0
    for entry in report.entries:
        if entry.kind != "ref" or entry.name.endswith("]"):
            continue
        if not _is_rewritable(entry.source_ref):
            continue
        rendered = []
        for part in entry.parts:
            raw = part.part.raw or original_part(part)
            role, bare = ref_role(raw)
            written_path = bare.startswith(part.part.path)
            owner = role_of.get(part.repo or "", primary) if part.repo else primary
            if part.status in ATTRIBUTED_STATUSES and written_path and owner != role:
                rendered.append(f"{owner} {bare}")
            else:
                rendered.append(raw)
        new_ref = ", ".join(rendered)
        if new_ref == entry.source_ref:
            continue
        try:
            text, index = replace_field_line(
                text, "source_ref", entry.source_ref, new_ref, cursor
            )
        except YamlWriteError:
            continue
        cursor = index + 1
        applied.append(f"{entry.source_ref} -> {new_ref}")
    if applied:
        path.write_text(text, encoding="utf-8")
    return applied


def _moved_by_hand(entry: EntryReport, statuses: tuple[str, ...]) -> bool:
    """Whether a ref the writer cannot regenerate has a part to move."""
    return any(
        part.status in statuses
        and part.start is not None
        and rendered_part(part) != original_part(part)
        for part in entry.parts
    )


def _recaled_ref(entry: EntryReport, statuses: tuple[str, ...]) -> str | None:
    """The source_ref with its moved parts rendered, None when none moves."""
    rendered = []
    touched = False
    for part in entry.parts:
        if part.status in statuses and part.start is not None:
            recaled = rendered_part(part)
            if recaled != original_part(part):
                touched = True
            rendered.append(recaled)
        else:
            rendered.append(original_part(part))
    return ", ".join(rendered) if touched else None


def _recale_statuses(
    path: Path, report: ProfileReport, accept_changed: bool
) -> tuple[str, ...] | None:
    """The statuses a recale moves, None when the profile must not move."""
    if report.pinned_tag:
        return None
    statuses = REBASE_STATUSES + (("CHANGED",) if accept_changed else ())
    blocking = [s for s in REVIEW_STATUSES if s not in statuses]
    if any((report.counts or {}).get(s) for s in blocking):
        return None
    blockers = pin_blockers(report, accept_changed)
    if blockers:
        # Something here will not move: an annotated ref, one under a mode
        # key, or a prose run this pass cannot rewrite without guessing.
        # bump_commit will refuse while it stands, and recaling the rest
        # would leave the profile describing two revisions at once. All or
        # nothing means the pin too, not only the refs.
        _refuse_recale(path, blockers)
        return None
    return statuses


def rebase_refs(
    path: Path, report: ProfileReport, accept_changed: bool = False
) -> list[str]:
    """Recale the line ranges of parts whose content is unchanged.

    All or nothing per profile. `source_commit` names the revision the refs
    are written against, so moving some refs to HEAD while others still
    describe the pinned revision would leave the profile self-contradictory,
    and the next comparison would read the pinned revision at line numbers
    that only make sense at HEAD. Prose citations move with everything else:
    only their located tokens are rewritten, the sentence stays.
    """
    statuses = _recale_statuses(path, report, accept_changed)
    if statuses is None:
        return []
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    citations = collect_citations(document, text)
    applied: list[str] = []
    refused: list[str] = []
    cursor = 0
    pos = 0
    prose_jobs: list[tuple[Citation, dict]] = []

    for entry in report.entries:
        citation, pos = _match_citation(citations, pos, entry)
        if citation is None:
            if any(_part_moves(part, statuses) for part in entry.parts):
                refused.append(
                    f"{entry.field or entry.name}: {entry.source_ref} "
                    "(the profile no longer carries it as reported)"
                )
            continue
        if entry.kind == "prose":
            moves = _prose_moves(entry, statuses)
            if moves:
                prose_jobs.append((citation, moves))
            continue
        if citation.label or entry.name.endswith("]"):
            # The ref lives under a mode key, not on a source_ref line. The
            # entry name check also holds when the report and the document
            # disagree: a stale report must not touch a line it never read.
            if _moved_by_hand(entry, statuses):
                refused.append(
                    f"{entry.name}: {entry.source_ref} (under a mode key, moved by hand)"
                )
            continue
        # Rewriting an annotated ref would drop the author's annotations.
        # It, like a ref with nothing to move, still consumes its line so a
        # later entry carrying the same ref cannot match it.
        new_ref = _recaled_ref(entry, statuses) if _is_rewritable(entry.source_ref) else None
        if new_ref is None:
            cursor = find_field_line(text, "source_ref", entry.source_ref, cursor) + 1
            continue
        text, index = replace_field_line(
            text, "source_ref", entry.source_ref, new_ref, cursor
        )
        cursor = index + 1
        set_scalar(citation.holder, citation.key, new_ref)
        applied.append(f"{entry.source_ref} -> {new_ref}")

    text, prose_applied, left = apply_prose_edits(text, prose_jobs, document)
    refused.extend(left)
    if refused:
        # A citation left on the pinned lines holds the pin, so writing the
        # others would leave the profile describing two revisions.
        _refuse_recale(path, refused)
        return []
    applied.extend(prose_applied)
    if applied:
        apply_edit(path, text, document)
    return applied


def _refuse_recale(path: Path, reasons: list[str]) -> None:
    """Name each citation that keeps a recale from being written."""
    for reason in reasons:
        print(f"{path.stem}: not recaled, cannot move {reason}", file=sys.stderr)


def _pending_refs(
    report: ProfileReport, movable: tuple[str, ...], document: dict | None
) -> int:
    """Parts of structured refs that ought to move and have not."""
    # A ref the writer regenerates is pending only while the file still
    # carries it as written: a bump run without the recale left lrps2's
    # SHIFTED refs on the old lines under the new pin. It is looked up at
    # its own field, never by its text alone: tr1x moved cut2 508->531 and
    # cut3 531->552, and cut3 read as pending on cut2's new value.
    refs_left: dict[tuple[str, str], int] = {}
    if document is not None:
        for citation in collect_citations(document):
            if citation.kind == "ref":
                for slot in ((citation.field, citation.ref), ("", citation.ref)):
                    refs_left[slot] = refs_left.get(slot, 0) + 1
    pending = 0
    for entry in report.entries or []:
        if entry.kind == "prose":
            continue
        if _is_rewritable(entry.source_ref) and not entry.name.endswith("]"):
            slot = (entry.field, entry.source_ref)
            if not refs_left.get(slot):
                continue
            refs_left[slot] -= 1
        pending += sum(
            1
            for part in entry.parts
            if part.status in movable
            and part.start is not None
            and rendered_part(part) != original_part(part)
        )
    return pending


def _pending_prose(
    report: ProfileReport, movable: tuple[str, ...], document: dict, text: str | None
) -> int:
    """Prose runs that ought to move and that the file does not carry moved."""
    pool: dict[tuple[str, str], int] = {}
    for citation in collect_citations(document, text):
        if citation.kind == "prose":
            slot = (citation.field, citation_key(citation.ref))
            pool[slot] = pool.get(slot, 0) + 1
    pending = 0
    for entry in report.entries or []:
        if entry.kind != "prose":
            continue
        moves = _prose_moves(entry, movable)
        if not moves:
            # Either nothing has to move, or the run cannot be written
            # without guessing, and the second case still blocks the pin.
            if any(_part_moves(part, movable) for part in entry.parts):
                pending += 1
            continue
        rendered = run_after_moves(
            [p.part for p in entry.parts], moves, entry.source_ref
        )
        if citation_key(rendered) == citation_key(entry.source_ref):
            continue
        slot = (entry.field, citation_key(rendered))
        if pool.get(slot, 0) > 0:
            pool[slot] -= 1
            continue
        pending += 1
    return pending


def pending_recale(
    report: ProfileReport, accept_changed: bool = False, text: str | None = None
) -> int:
    """Parts that ought to move but the writer has not moved.

    An annotated ref cannot be regenerated without losing its prose, so its
    parts stay on the pinned line numbers. Advancing the pin while they do
    would leave the profile describing two revisions at once.

    Prose runs are judged on the file as it stands: a run that should move
    counts as pending until the document actually carries its recaled form,
    so the pin cannot advance over prose that still describes the old
    revision, whatever the reason it was not rewritten.
    """
    movable = REBASE_STATUSES + (("CHANGED",) if accept_changed else ())
    document = yaml.safe_load(text) if text is not None else None
    pending = _pending_refs(report, movable, document)
    if document is None:
        return pending
    return pending + _pending_prose(report, movable, document, text)
