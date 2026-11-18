"""Finding a cited block again: anchoring, renames, shifts and the self-check at a pin."""

from __future__ import annotations

import difflib
import posixpath
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace

from core.upstream import CompareResult, find_renamed
from model.sourceref import RefPart, is_binary_citation
from profiling.citations import is_external_citation
from profiling.repos import HEAD, PIN


STATUS_ORDER = (
    "ANCHORED", "UNCHECKED", "EXTERNAL", "BINARY", "SHIFTED", "RENAMED", "MOVED",
    "AMBIGUOUS", "CHANGED", "GONE",
)
REVIEW_STATUSES = ("CHANGED", "GONE", "AMBIGUOUS")
REBASE_STATUSES = ("SHIFTED", "RENAMED", "MOVED")

WIDEN_STEPS = (0, 3, 6, 12, 25, 50)
# A 30k-line driver diffs in about five seconds, and the biggest files the
# corpus cites sit just above that. The cap stays as a guard against
# pathological inputs, not as a limit on real source files.
# The fallback mapping is a full sequence diff, and it only runs once exact
# anchoring has failed, which is rare. openbor.c is the largest file any
# profile cites, 55k lines against 57k, and diffing the pair takes nine
# seconds. The ceiling sits above it so that one resolves, and still stops a
# pathological pair from stalling a sweep of every profile.
MAX_MATCH_LINES = 60000


HEADER_SUFFIXES = (".h", ".hpp", ".hh", ".hxx", ".inc", ".inl")


@dataclass(frozen=True)
class AnchorResult:
    status: str
    start: int | None
    end: int | None
    candidates: list[int]
    reason: str | None = None


@dataclass(frozen=True)
class PartResult:
    part: RefPart
    status: str
    new_path: str | None
    start: int | None
    end: int | None
    candidates: list[int]
    reason: str | None = None
    repo: str | None = None
    head_url: str | None = None


def worst_status(statuses: Iterable[str]) -> str:
    """Severity of an entry is the worst severity among its parts."""
    worst = "ANCHORED"
    for status in statuses:
        if STATUS_ORDER.index(status) > STATUS_ORDER.index(worst):
            worst = status
    return worst


def _normalize(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines]


def _find_all(haystack: list[str], needle: list[str]) -> list[int]:
    """Zero-based offsets where the needle sequence occurs."""
    size = len(needle)
    if not size or size > len(haystack):
        return []
    first = needle[0]
    return [
        i for i in range(len(haystack) - size + 1)
        if haystack[i] == first and haystack[i : i + size] == needle
    ]


def _map_index(
    opcodes: list[tuple[str, int, int, int, int]], index: int
) -> int | None:
    """Line of HEAD that a pinned line became.

    A replace block of equal size edits each line in place (a column added to
    every row of a table), so its lines map one to one like an equal block.
    Collapsed onto the first line, eight refs citing eight rows all landed on
    the first row.
    """
    for tag, i1, i2, j1, j2 in opcodes:
        if i1 <= index < i2:
            in_place = tag == "equal" or (tag == "replace" and i2 - i1 == j2 - j1)
            return j1 + (index - i1) if in_place else j1
    return None


_OPCODE_CACHE: dict[tuple[tuple[str, ...], tuple[str, ...]], list] = {}
_OPCODE_CACHE_SIZE = 8


def _opcodes(pin: list[str], head: list[str]) -> list:
    """Opcodes for one pair of revisions, computed once per run.

    Every ref citing the same file would otherwise redo the same diff, and a
    driver of thirty thousand lines takes seconds each time. Keyed by the
    lines themselves: anchor_block hands over lists it builds and frees, and
    an id() key served one file's opcodes to the next pair at the same
    addresses.
    """
    key = (tuple(pin), tuple(head))
    cached = _OPCODE_CACHE.pop(key, None)
    if cached is None:
        cached = difflib.SequenceMatcher(
            None, pin, head, autojunk=False
        ).get_opcodes()
    _OPCODE_CACHE[key] = cached
    while len(_OPCODE_CACHE) > _OPCODE_CACHE_SIZE:
        del _OPCODE_CACHE[next(iter(_OPCODE_CACHE))]
    return cached


def _map_changed(pin: list[str], head: list[str], lo: int, hi: int) -> AnchorResult:
    """Map a pinned range onto HEAD once exact anchoring has failed."""
    if len(pin) > MAX_MATCH_LINES or len(head) > MAX_MATCH_LINES:
        return AnchorResult(
            "CHANGED", None, None, [], f"file over {MAX_MATCH_LINES} lines"
        )
    opcodes = _opcodes(pin, head)
    # A file whose every line was edited in place keeps no equal block, yet
    # its lines still map one to one: fheroes2 version.txt holds one line,
    # 1.0.11 at the pin and 1.1.17 at HEAD, and read GONE.
    rewritten_in_place = len(opcodes) == 1 and (
        opcodes[0][0] == "replace"
        and opcodes[0][2] - opcodes[0][1] == opcodes[0][4] - opcodes[0][3]
    )
    if not rewritten_in_place and not any(tag == "equal" for tag, *_ in opcodes):
        return AnchorResult("GONE", None, None, [])
    new_lo = _map_index(opcodes, lo)
    new_hi = _map_index(opcodes, max(lo, hi - 1))
    if new_lo is None or new_hi is None:
        return AnchorResult("GONE", None, None, [])
    return AnchorResult("CHANGED", new_lo + 1, max(new_lo, new_hi) + 1, [])


def anchor_block(
    pin_lines: list[str], head_lines: list[str], start: int, end: int
) -> AnchorResult:
    """Locate the pinned line range inside the HEAD revision of a file."""
    pin = _normalize(pin_lines)
    head = _normalize(head_lines)
    lo, hi = start - 1, end
    if lo < 0 or hi > len(pin):
        return AnchorResult("GONE", None, None, [], "cited range ends past the end of the file")
    if not any(pin[lo:hi]):
        return AnchorResult("CHANGED", None, None, [], "cited range is blank")

    candidates: list[int] = []
    for pad in WIDEN_STEPS:
        a = max(0, lo - pad)
        b = min(len(pin), hi + pad)
        hits = _find_all(head, pin[a:b])
        offset = lo - a
        if len(hits) == 1:
            new_start = hits[0] + offset + 1
            new_end = new_start + (hi - lo) - 1
            status = "ANCHORED" if new_start == start else "SHIFTED"
            return AnchorResult(status, new_start, new_end, [])
        if not hits:
            break
        candidates = [h + offset + 1 for h in hits]
    else:
        return AnchorResult("AMBIGUOUS", None, None, candidates)

    if candidates:
        return AnchorResult("AMBIGUOUS", None, None, candidates)
    return _map_changed(pin, head, lo, hi)


NUDGE_WINDOW = 60


def nudge_to_declared(
    pin_lines: list[str], start: int, end: int, tokens: Sequence[str]
) -> tuple[int, int] | None:
    """Move a cited range onto the nearest line carrying a declared value.

    Some refs sit a few lines off their subject, and a few land on a blank
    line, which anchors nothing. When the entry declares a hash or a name and
    that value appears close by, the ref plainly meant that line.
    """
    if not tokens:
        return None
    if end > start and any(line.strip() for line in pin_lines[start - 1:end]):
        # A range over code cites that code (a loading function), not the
        # value beside it. Moved onto the nearest name, ymir's 598-618 left
        # load_rom_cartridge() and a real change read as a silent SHIFTED.
        return None
    lowered = [line.lower() for line in pin_lines]
    hits = [
        i + 1
        for i, line in enumerate(lowered)
        if any(token in line for token in tokens)
    ]
    if not hits:
        return None
    nearest = min(hits, key=lambda n: abs(n - start))
    if abs(nearest - start) > NUDGE_WINDOW or nearest == start:
        return None
    if sum(1 for h in hits if abs(h - nearest) <= 1) > 1:
        return None
    return nearest, nearest + (end - start)


def resolve_rename(
    result: CompareResult, path: str, head_paths: Iterable[str] = ()
) -> tuple[str | None, list[str]]:
    """New path of a moved file, or the candidates when several match.

    The comparison is authoritative when it reports the rename. Otherwise the
    HEAD tree is searched by basename, then by stem: a C++ file rewritten in C
    keeps its stem and loses its basename.
    """
    renamed = find_renamed(result, path)
    if renamed:
        return renamed, []
    pool = list(head_paths) or [change.path for change in result.files]
    base = posixpath.basename(path)
    matches = _narrow(
        [p for p in pool if p != path and posixpath.basename(p) == base], path
    )
    if len(matches) == 1:
        return matches[0], []
    if not matches:
        stem = base.rsplit(".", 1)[0]
        matches = _narrow(
            [
                p
                for p in pool
                if p != path and posixpath.basename(p).rsplit(".", 1)[0] == stem
            ],
            path,
        )
        if len(matches) == 1:
            return matches[0], []
    return None, matches


def _is_header(path: str) -> bool:
    return path.lower().endswith(HEADER_SUFFIXES)


def _narrow(matches: list[str], path: str) -> list[str]:
    """Prefer candidates of the same kind, then of the same directory.

    A stem search on `ss.cpp` matches both `ss.c` and `ss.h`, and only one of
    them is the implementation the ref meant.
    """
    if len(matches) < 2:
        return matches
    kind = [p for p in matches if _is_header(p) == _is_header(path)]
    if len(kind) == 1:
        return kind
    pool = kind or matches
    directory = posixpath.dirname(path)
    same = [p for p in pool if posixpath.dirname(p) == directory]
    return same if len(same) == 1 else pool


def locate_by_declared_value(
    head_lines: list[str], anchored: AnchorResult, tokens: Sequence[str]
) -> tuple[int, int, str] | None:
    """Follow a ref whose subject can still be pinpointed at HEAD.

    Two cases carry enough evidence to move a ref without judging the edit
    itself: the mapped range already contains the declared value, or the value
    occurs exactly once in the whole file. A value occurring several times is
    left alone, since nothing says which one the ref meant.
    """
    lowered = [line.lower() for line in head_lines]
    if anchored.start is not None:
        end = anchored.end or anchored.start
        block = "\n".join(lowered[anchored.start - 1 : end])
        if any(token in block for token in tokens):
            return (
                anchored.start,
                end,
                "content edited, declared value present in the new range",
            )
    hits = [
        i + 1
        for i, line in enumerate(lowered)
        if any(token in line for token in tokens)
    ]
    if len(hits) == 1:
        return hits[0], hits[0], "declared value occurs once at HEAD"
    return None


def _written_against_head(part: RefPart, head_lines: list[str] | None) -> bool:
    """Whether the cited line exists at HEAD, which is where it was written."""
    return (
        head_lines is not None
        and part.start is not None
        and part.start <= len(head_lines)
    )


# What the rename search answers when a tree it needed came back truncated:
# a file missing from a partial listing may still exist, so absence is not
# established. eden's fs_paths.h and path_util.cpp were reported GONE.
TREE_TRUNCATED = "(HEAD tree truncated by the forge)"


def _unanchorable(part: RefPart) -> PartResult | None:
    """The verdict on a part that cites no source path of a declared tree."""
    if is_binary_citation(part.path):
        return PartResult(
            part, "BINARY", None, None, None, [],
            "cites a shipped binary, no source path to anchor",
        )
    if is_external_citation(part.path):
        return PartResult(
            part, "EXTERNAL", None, None, None, [],
            "names a project the profile does not declare",
        )
    return None


def _rename_verdict(
    part: RefPart, candidates: list[str], slug: str | None, url: str | None
) -> PartResult:
    """What a part absent at HEAD reads as when no rename was found."""
    if candidates == [TREE_TRUNCATED]:
        return PartResult(
            part, "AMBIGUOUS", None, None, None, [],
            "absent from a HEAD tree the forge truncated: "
            "the file may still exist",
            slug, url,
        )
    if candidates:
        return PartResult(
            part,
            "AMBIGUOUS",
            None,
            None,
            None,
            [],
            f"{len(candidates)} candidates: {', '.join(candidates[:5])}",
            slug,
            url,
        )
    return PartResult(
        part,
        "GONE",
        None,
        None,
        None,
        [],
        "absent at HEAD, no rename found",
        slug,
        url,
    )


def _anchor_range(
    part: RefPart,
    start: int,
    pin_lines: list[str],
    head_lines: list[str],
    tokens: Sequence[str],
) -> tuple[AnchorResult, str, str | None]:
    """The cited range carried from the pin to HEAD: anchor, status, note."""
    end = part.last
    anchored = anchor_block(pin_lines, head_lines, start, end)
    note = anchored.reason
    if anchored.status in REVIEW_STATUSES:
        nudged = nudge_to_declared(pin_lines, start, end, tokens)
        if nudged is not None:
            retry = anchor_block(pin_lines, head_lines, *nudged)
            if retry.status not in REVIEW_STATUSES:
                anchored = retry
                note = f"cited line was {nudged[0] - start:+d} off its subject"
    status = anchored.status
    if status in ("CHANGED", "GONE") and tokens:
        located = locate_by_declared_value(head_lines, anchored, tokens)
        if located is not None:
            moved_start, moved_end, why = located
            anchored = AnchorResult("MOVED", moved_start, moved_end, [])
            status, note = "MOVED", why
    return anchored, status, note


def _pin_missing(
    part: RefPart, pin_lines: list[str] | None, head_lines: list[str],
) -> str | None:
    """Why the pinned revision cannot carry the cited range, None when it can."""
    if pin_lines is None:
        # Present at HEAD, absent at the pin, and the cited range fits the
        # HEAD file: the ref was written against HEAD while source_commit
        # still names an older revision. Saying "missing" sends the reader
        # hunting for a move that never happened: the fix is the pin.
        reason = "pin revision missing"
        if _written_against_head(part, head_lines):
            reason = "written against HEAD, pin names an older revision"
        return reason
    if part.last > len(pin_lines):
        # The file is there and the line is not yet: the pinned revision is
        # shorter than the one the ref was written against. nestopia cited
        # the palette and database loads at 2041 and 2063, which is where
        # HEAD carries them, over a pin four hundred lines shorter. A range
        # that only ends past the file is no better: dolphin cited 239-323 in
        # a 317-line NANDImporter.cpp, and the block found above the end
        # anchored it.
        return (
            "written against HEAD, pin names an older revision"
            if _written_against_head(part, head_lines)
            else "cited range ends past the end of the file"
        )
    return None


def anchor_part(
    part: RefPart,
    fetch: Callable[[str, str, int | None, Sequence[str]], list[str] | None],
    rename_getter: Callable[[str], tuple[str | None, list[str]]],
    describe: Callable[..., tuple[str | None, str | None, str]] | None = None,
    tokens: Sequence[str] = (),
) -> PartResult:
    """Locate one reference part at HEAD, following a rename when needed.

    `describe(path)` returns (repo slug, raw URL at HEAD) for the repository
    that owns the path, or (None, None) when the caller does not track it.
    """
    unanchorable = _unanchorable(part)
    if unanchorable is not None:
        return unanchorable
    slug, url, actual = (
        describe(part.path, part.start, tokens) if describe
        else (None, None, part.path)
    )
    head_lines = fetch(HEAD, part.path, part.start, tokens)
    path = actual
    renamed = actual != part.path

    if head_lines is None:
        moved, candidates = rename_getter(part.path)
        if moved is None:
            return _rename_verdict(part, candidates, slug, url)
        path = moved
        head_lines = fetch(HEAD, path, part.start, tokens)
        if head_lines is None:
            return PartResult(
                part, "GONE", None, None, None, [], None, slug, url
            )
        renamed = True
        if describe:
            slug, url, _ = describe(path)

    if part.start is None:
        status = "RENAMED" if renamed else "ANCHORED"
        return PartResult(
            part, status, path if renamed else None, None, None, [], None, slug, url
        )

    pin_lines = fetch(PIN, part.path, part.start, tokens)
    if pin_lines is None and path != part.path:
        # A ref may cite a bare filename the tree search resolved at HEAD. The
        # same resolved path usually holds at the pin. A genuine rename keeps
        # the old path at the pin, which is why that one is tried first.
        pin_lines = fetch(PIN, path, part.start, tokens)
    reason = _pin_missing(part, pin_lines, head_lines)
    if reason is not None or pin_lines is None:
        return PartResult(part, "GONE", None, None, None, [], reason, slug, url)

    anchored, status, note = _anchor_range(part, part.start, pin_lines, head_lines, tokens)
    if renamed and status in ("ANCHORED", "SHIFTED"):
        status = "RENAMED"
    return PartResult(
        part,
        status,
        path if renamed else None,
        anchored.start,
        anchored.end,
        anchored.candidates,
        note,
        slug,
        url,
    )


SHIFT_SUPPORT = 3

# Lines read past a blank cited line when scoring which repository owns it.
BLANK_LOOKAHEAD = 5


def dominant_shifts(
    parts: Iterable[PartResult], support: int = SHIFT_SUPPORT
) -> dict[str, int]:
    """Most common line shift per file, taken from the unambiguous anchors.

    A file whose refs mostly moved by the same amount gives strong evidence
    for the ones that stayed ambiguous: repetitive tables, as in the NeoGeo
    driver, match a cited line in several places, and only one of them sits
    where the rest of the file moved to.
    """
    by_file: dict[str, dict[int, int]] = {}
    for part in parts:
        if part.status not in ("ANCHORED", "SHIFTED"):
            continue
        if part.start is None or part.part.start is None:
            continue
        counts = by_file.setdefault(part.part.path, {})
        delta = part.start - part.part.start
        counts[delta] = counts.get(delta, 0) + 1
    shifts = {}
    for path, counts in by_file.items():
        delta, seen = max(counts.items(), key=lambda kv: kv[1])
        if seen >= support:
            shifts[path] = delta
    return shifts


def resolve_by_shift(part: PartResult, shifts: dict[str, int]) -> PartResult:
    """Settle an ambiguous part when one candidate matches the file's shift."""
    if part.status != "AMBIGUOUS" or not part.candidates:
        return part
    if part.part.start is None or part.part.path not in shifts:
        return part
    wanted = part.part.start + shifts[part.part.path]
    if part.candidates.count(wanted) != 1:
        return part
    span = (part.part.end or part.part.start) - part.part.start
    return PartResult(
        part.part,
        "ANCHORED" if wanted == part.part.start else "SHIFTED",
        part.new_path,
        wanted,
        wanted + span,
        [],
        f"settled by the {shifts[part.part.path]:+d} line shift of its file",
        part.repo,
        part.head_url,
    )


def refuse_collapsing_moves(parts: list[PartResult]) -> list[PartResult]:
    """Hold back a recale that would land on another part of the same ref.

    Two parts of one source_ref cite two places on purpose. dosbox_pure cited
    the SHA-1 line of mt32emu.h and the ROMInfo line that ties it to a file
    name, under two repository words: the second was self-checked alone,
    found the hash once, and read MOVED onto the first line. Recaling it
    would drop the ROMInfo citation without a word, so the part goes to
    review instead.
    """
    cited = {
        (p.part.path, p.part.start, p.part.last)
        for p in parts if p.part.start is not None
    }
    held = []
    for part in parts:
        target = (part.new_path or part.part.path, part.start, part.end or part.start)
        own = (part.part.path, part.part.start, part.part.last)
        if (
            part.status in REBASE_STATUSES and part.start is not None
            and target != own and target in cited
        ):
            part = replace(
                part, status="AMBIGUOUS", candidates=[part.start],
                reason="lands on a line another part of this ref already cites",
            )
        held.append(part)
    return held


SELF_CHECK_CONTEXT = 2


def verify_at_pin(
    part: RefPart,
    pin_lines: list[str] | None,
    tokens: Sequence[str],
    hash_tokens: Sequence[str] = (),
) -> PartResult:
    """Check a ref against its own revision instead of against HEAD.

    A profile pinned to a superseded tag documents a program HEAD no longer
    contains, so comparing the two says nothing. What can still be checked is
    self-consistency: does the cited range carry the value the entry declares?
    """
    unanchorable = _unanchorable(part)
    if unanchorable is not None:
        return unanchorable
    if pin_lines is None:
        return PartResult(
            part, "GONE", None, None, None, [], "absent at the pinned revision"
        )
    if part.start is None:
        return PartResult(part, "ANCHORED", None, None, None, [])
    if part.last > len(pin_lines):
        return PartResult(
            part, "GONE", None, None, None, [], "beyond the end of the file"
        )
    if not tokens:
        # Nothing to look for: an entry with neither a hash nor a name (an
        # analysis block, a `filename:` field) cannot be checked against its
        # own revision. Calling it anchored made the check vacuously true, and
        # a pin advanced without a recale hid a ref that had become false.
        return PartResult(
            part, "UNCHECKED", None, None, None, [],
            "entry declares no value to look for",
        )
    # An archive ref cites the line declaring the set. Its members follow, one
    # per line, so the window reaches forward as far as the entry has members.
    reach = SELF_CHECK_CONTEXT + len(tokens)
    lo = max(0, part.start - 1 - SELF_CHECK_CONTEXT)
    hi = min(len(pin_lines), part.last + reach)
    window = "\n".join(pin_lines[lo:hi]).lower()
    if any(token in window for token in tokens):
        return PartResult(part, "ANCHORED", None, None, None, [])
    return _value_elsewhere(part, pin_lines, hash_tokens)


def _value_elsewhere(
    part: RefPart, pin_lines: list[str], hash_tokens: Sequence[str]
) -> PartResult:
    """A part whose cited window lacks the value, judged by where it is."""
    # A ref that cites loading logic never spells the value out, so its absence
    # here proves nothing. Only finding the value somewhere else in the file
    # shows the ref points at the wrong place, and only a hash carries that
    # weight. A filename fragment matches by coincidence: `tyrian2` hits every
    # line naming `tyrian2.c`, and a name built at runtime from a format
    # string appears nowhere at all.
    if not hash_tokens:
        return PartResult(part, "ANCHORED", None, None, None, [])
    elsewhere = sorted(
        {
            index
            for index, line in enumerate(pin_lines, 1)
            for token in hash_tokens
            if token.lower() in line.lower()
        }
    )
    if not elsewhere:
        return PartResult(part, "ANCHORED", None, None, None, [])
    if len(elsewhere) > 1:
        return PartResult(
            part, "AMBIGUOUS", None, None, None, elsewhere,
            "declared value carried by several lines",
        )
    # Content-level evidence, stronger than a line-shift heuristic: the value
    # sits on exactly one line, so the recale target is not a guess.
    return PartResult(
        part, "MOVED", None, elsewhere[0], elsewhere[0], elsewhere,
        "declared value occurs once at the pinned revision",
    )


def reconcile_self_check(
    parts: list[PartResult], eligible: list[bool] | None = None
) -> list[PartResult]:
    """Judge a self-checked entry whole rather than part by part.

    A ref often cites both the table carrying the value and the code that
    loads the file. Once one part anchors on the value, the others in the
    SAME file describe behaviour and cannot be judged by value: the checker
    would only rediscover the value where the first part already points. A
    part in another file carries its own value and is judged on it: geolith's
    jg.c part, sixteen lines off, was settled by an anchored libretro.c part.
    A structurally absent part still counts, and a part that was compared
    against HEAD rather than self-checked is never rewritten.
    """
    eligible = eligible if eligible is not None else [True] * len(parts)
    # The settled part lies in the tree its anchor was found in: without the
    # repository, attribution wrote dosbox-pure-unleashed's ROMInfo line
    # under `source`, a repository that carries no mt32emu.h.
    anchored_files: dict[str, str | None] = {}
    for part, ok in zip(parts, eligible):
        if ok and part.status == "ANCHORED":
            anchored_files.setdefault(part.part.path, part.repo)
    kept = ("ANCHORED", "GONE", "EXTERNAL", "BINARY")
    return [
        PartResult(
            part.part, "ANCHORED", None, None, None, [],
            repo=anchored_files[part.part.path],
        )
        if ok and part.status not in kept and part.part.path in anchored_files
        else part
        for part, ok in zip(parts, eligible)
    ]
