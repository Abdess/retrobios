#!/usr/bin/env python3
"""Confront emulator profiles with their upstream source.

Anchors every source_ref of a profile against the commit the profile was
written at and against upstream HEAD, separating what is mechanically
recalable from what needs the code read again.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import posixpath
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(__file__))

import upstream
from common import load_emulator_profiles
from upstream import CompareResult, find_renamed

DEFAULT_CACHE = ".cache/upstream"
ANON_QUOTA = 60
TRIAGE_PATH_SAMPLE = 5

STATUS_ORDER = (
    "ANCHORED", "EXTERNAL", "SHIFTED", "RENAMED", "MOVED", "AMBIGUOUS",
    "CHANGED", "GONE",
)
REVIEW_STATUSES = ("CHANGED", "GONE", "AMBIGUOUS")
REBASE_STATUSES = ("SHIFTED", "RENAMED", "MOVED")

WIDEN_STEPS = (0, 3, 6, 12, 25, 50)
# A 30k-line driver diffs in about five seconds, and the biggest files the
# corpus cites sit just above that. The cap stays as a guard against
# pathological inputs, not as a limit on real source files.
MAX_MATCH_LINES = 40000

PIN = "pin"
HEAD = "head"

_REF_RE = re.compile(r"^(?P<path>[^:]+?)(?::(?P<start>\d+)(?:-(?P<end>\d+))?)?$")
_BARE_RANGE_RE = re.compile(r"^:?(\d+(?:-\d+)?)$")
HEADER_SUFFIXES = (".h", ".hpp", ".hh", ".hxx", ".inc", ".inl")
_SPLIT_RE = re.compile(r"[,;]")
_ANNOTATION_RE = re.compile(r"\s*\([^)]*\)?")
_LOCATED_RE = re.compile(r"^[^\s:]+:\d+(?:-\d+)?$")


@dataclass(frozen=True)
class RefPart:
    path: str
    start: int | None
    end: int | None
    raw: str = ""


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


@dataclass(frozen=True)
class RepoView:
    """One repository a profile cites, at the two revisions under comparison."""

    repo: object
    pin: str
    head: str
    origin: str
    field: str


def parse_source_ref(ref: str) -> tuple[str, int | None, int | None]:
    """Split 'path/file.cpp:123-129' into (path, start, end)."""
    m = _REF_RE.match(ref.strip())
    if not m:
        return ref.strip(), None, None
    start = int(m.group("start")) if m.group("start") else None
    end = int(m.group("end")) if m.group("end") else start
    return m.group("path"), start, end


def source_ref_values(value) -> list[tuple[str, str]]:
    """Flatten a source_ref into (label, refs) pairs.

    Most entries hold a plain string. `ymir` keys its refs by mode instead,
    since its standalone and libretro builds read different files.
    """
    if isinstance(value, dict):
        return [(str(k), str(v)) for k, v in value.items() if v]
    return [("", str(value))] if value else []


def split_source_ref(ref: str) -> list[RefPart]:
    """A source_ref may carry several references.

    Separators are the comma and the semicolon. A part reduced to a line or a
    line range continues the previous part's file: `geo.c:234-243, 273-285`
    cites two ranges of the same file, a form used by 430 parts across 69
    profiles. Parenthetical annotations are prose and are dropped: 285 entries
    across 50 profiles carry them.
    """
    parts: list[RefPart] = []
    for raw in split_outside_parentheses(str(ref or "")):
        chunk = _trim_prose(_ANNOTATION_RE.sub("", raw).strip())
        if not chunk:
            continue
        bare = _BARE_RANGE_RE.match(chunk)
        if bare and parts:
            start, _, end = bare.group(1).partition("-")
            parts.append(
                RefPart(parts[-1].path, int(start), int(end or start), raw)
            )
            continue
        path, start_line, end_line = parse_source_ref(chunk)
        parts.append(RefPart(path, start_line, end_line, raw))
    return parts


def split_outside_parentheses(text: str) -> list[str]:
    """Split on commas and semicolons, ignoring those inside an annotation.

    Each chunk keeps its annotation, so a rewrite can put the prose back.
    """
    chunks: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if char in ",;" and depth == 0:
            chunks.append("".join(current))
            current = []
        else:
            current.append(char)
    chunks.append("".join(current))
    return [c for c in (chunk.strip() for chunk in chunks) if c]


def _trim_prose(chunk: str) -> str:
    """Drop a trailing comment written without parentheses.

    `libretro.cpp:1520-1521 candidates_a1200` cites a location followed by a
    note. The leading token is kept only when it already reads as a reference,
    so `munt ROMInfo.cpp`, which names an external project, stays intact and
    is reported rather than silently truncated to `munt`.
    """
    if " " not in chunk:
        return chunk
    head = chunk.split(" ", 1)[0]
    if _LOCATED_RE.match(head) or _BARE_RANGE_RE.match(head):
        return head
    return chunk


def collect_tokens(entry: dict) -> list[str]:
    """Values declared by one file entry: hashes, then name as fallback."""
    tokens: list[str] = []
    for field in ("sha1", "md5", "crc32", "sha256", "known_hash_adler32"):
        val = entry.get(field)
        vals = val if isinstance(val, list) else [val] if val else []
        for v in vals:
            v = str(v).lower().removeprefix("0x")
            if v:
                tokens.append(v)
    if not tokens:
        name = entry.get("name", "")
        if name:
            tokens.append(os.path.basename(name).lower())
    return tokens


def is_external_citation(path: str) -> bool:
    """True when a ref names a project rather than a path in a known repo.

    `munt ROMInfo.cpp` and `Nuked-SC55-CLAP rom_io.cpp` cite where a ROM is
    identified inside a dependency the profile does not declare, so no
    revision of the declared repositories can confirm or deny them. Reporting
    them as broken would be wrong: they are simply out of reach.
    """
    if " " not in path:
        return False
    head = path.split(" ", 1)[0]
    return "/" not in head and "." not in head


def _anchor_tokens(entry: dict) -> list[str]:
    """Values worth searching for when a cited line misses its subject.

    Archive entries are named `stvbios.zip` while the driver source writes the
    set name alone, so the stem is searched as well as the full name.
    """
    tokens = collect_tokens(entry)
    name = os.path.basename(str(entry.get("name", ""))).lower()
    stem = name.rsplit(".", 1)[0]
    if stem and stem not in tokens and len(stem) > 2:
        tokens.append(stem)
    return tokens


def worst_status(statuses) -> str:
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
    hits = []
    for i in range(len(haystack) - size + 1):
        if haystack[i] == first and haystack[i : i + size] == needle:
            hits.append(i)
    return hits


def _map_index(opcodes, index: int) -> int | None:
    for tag, i1, i2, j1, j2 in opcodes:
        if i1 <= index < i2:
            return j1 + (index - i1) if tag == "equal" else j1
    return None


_OPCODE_CACHE: dict[tuple[int, int], list] = {}


def _opcodes(pin: list[str], head: list[str]) -> list:
    """Opcodes for one pair of revisions, computed once per run.

    Every ref citing the same file would otherwise redo the same diff, and a
    driver of thirty thousand lines takes seconds each time.
    """
    key = (id(pin), id(head))
    cached = _OPCODE_CACHE.get(key)
    if cached is None:
        cached = difflib.SequenceMatcher(
            None, pin, head, autojunk=False
        ).get_opcodes()
        _OPCODE_CACHE[key] = cached
    return cached


def _map_changed(pin: list[str], head: list[str], lo: int, hi: int) -> AnchorResult:
    """Map a pinned range onto HEAD once exact anchoring has failed."""
    if len(pin) > MAX_MATCH_LINES or len(head) > MAX_MATCH_LINES:
        return AnchorResult(
            "CHANGED", None, None, [], f"file over {MAX_MATCH_LINES} lines"
        )
    opcodes = _opcodes(pin, head)
    if not any(tag == "equal" for tag, *_ in opcodes):
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
    if lo < 0 or lo >= len(pin):
        return AnchorResult("GONE", None, None, [])
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
    pin_lines: list[str], start: int, end: int, tokens
) -> tuple[int, int] | None:
    """Move a cited range onto the nearest line carrying a declared value.

    Some refs sit a few lines off their subject, and a few land on a blank
    line, which anchors nothing. When the entry declares a hash or a name and
    that value appears close by, the ref plainly meant that line.
    """
    if not tokens:
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
    result: CompareResult, path: str, head_paths=()
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
    head_lines: list[str], anchored: AnchorResult, tokens
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


def anchor_part(
    part: RefPart, fetch, rename_getter, describe=None, tokens=()
) -> PartResult:
    """Locate one reference part at HEAD, following a rename when needed.

    `describe(path)` returns (repo slug, raw URL at HEAD) for the repository
    that owns the path, or (None, None) when the caller does not track it.
    """
    if is_external_citation(part.path):
        return PartResult(
            part, "EXTERNAL", None, None, None, [],
            "names a project the profile does not declare",
        )
    slug, url, actual = (
        describe(part.path) if describe else (None, None, part.path)
    )
    head_lines = fetch(HEAD, part.path)
    path = actual
    renamed = actual != part.path

    if head_lines is None:
        moved, candidates = rename_getter(part.path)
        if moved is None:
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
        path = moved
        head_lines = fetch(HEAD, path)
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

    pin_lines = fetch(PIN, part.path)
    if pin_lines is None and path != part.path:
        # A ref may cite a bare filename the tree search resolved at HEAD; the
        # same resolved path usually holds at the pin. A genuine rename keeps
        # the old path at the pin, which is why that one is tried first.
        pin_lines = fetch(PIN, path)
    if pin_lines is None:
        return PartResult(
            part, "GONE", None, None, None, [], "pin revision missing", slug, url
        )

    end = part.end or part.start
    anchored = anchor_block(pin_lines, head_lines, part.start, end)
    note = anchored.reason
    if anchored.status in REVIEW_STATUSES:
        nudged = nudge_to_declared(pin_lines, part.start, end, tokens)
        if nudged is not None:
            retry = anchor_block(pin_lines, head_lines, *nudged)
            if retry.status not in REVIEW_STATUSES:
                anchored = retry
                note = f"cited line was {nudged[0] - part.start:+d} off its subject"
    status = anchored.status
    if status in ("CHANGED", "GONE") and tokens:
        located = locate_by_declared_value(head_lines, anchored, tokens)
        if located is not None:
            start, end, why = located
            anchored = AnchorResult("MOVED", start, end, [])
            status, note = "MOVED", why
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


def dominant_shifts(parts, support: int = SHIFT_SUPPORT) -> dict[str, int]:
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


@dataclass
class EntryReport:
    name: str
    source_ref: str
    status: str
    parts: list[PartResult]


@dataclass
class ProfileReport:
    name: str
    repo: str | None = None
    repos: list[str] = None
    pinned_tag: str | None = None
    host: str | None = None
    pin: str | None = None
    pin_origin: str | None = None
    head: str | None = None
    entries: list[EntryReport] = None
    skipped: str | None = None
    counts: dict[str, int] = None

    def needs_review(self) -> int:
        counts = self.counts or {}
        return sum(counts.get(status, 0) for status in REVIEW_STATUSES)


def select_repo(profile: dict) -> upstream.Repo | None:
    """Repository the profile was read from: source first, then upstream."""
    for field in ("source", "upstream"):
        repo = upstream.parse_repo(str(profile.get(field) or ""))
        if repo is not None:
            return repo
    return None


def resolve_pin(
    profile: dict, repo, cache_dir: str, offline: bool, field: str = "source"
) -> tuple[str | None, str | None]:
    """Commit the profile was written at, and how it was obtained.

    `field` selects which declared pin applies: `source_commit` for the port
    the profile was read from, `upstream_commit` for the original project.
    """
    pinned = profile.get(f"{field}_commit")
    if pinned:
        return str(pinned), f"{field}_commit"
    date = str(profile.get("profiled_date") or "")
    if not date:
        return None, None
    sha = upstream.resolve_commit_at(repo, date, cache_dir, offline)
    return sha, (f"profiled_date {date}" if sha else None)


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
    for field in ("source", "upstream"):
        repo = upstream.parse_repo(str(profile.get(field) or ""))
        if repo is None or (repo.host, repo.slug) in seen:
            continue
        pin, origin = resolve_pin(profile, repo, cache_dir, offline, field)
        if not pin:
            continue
        head = upstream.resolve_head(repo, cache_dir, offline)
        if not head:
            continue
        seen.add((repo.host, repo.slug))
        views.append(RepoView(repo, pin, head, origin, field))
    return views


SELF_CHECK_CONTEXT = 2


def verify_at_pin(part: RefPart, pin_lines, tokens) -> PartResult:
    """Check a ref against its own revision instead of against HEAD.

    A profile pinned to a superseded tag documents a program HEAD no longer
    contains, so comparing the two says nothing. What can still be checked is
    self-consistency: does the cited range carry the value the entry declares?
    """
    if is_external_citation(part.path):
        return PartResult(
            part, "EXTERNAL", None, None, None, [],
            "names a project the profile does not declare",
        )
    if pin_lines is None:
        return PartResult(
            part, "GONE", None, None, None, [], "absent at the pinned revision"
        )
    if part.start is None:
        return PartResult(part, "ANCHORED", None, None, None, [])
    if part.start > len(pin_lines):
        return PartResult(
            part, "GONE", None, None, None, [], "beyond the end of the file"
        )
    if not tokens:
        return PartResult(part, "ANCHORED", None, None, None, [])
    lo = max(0, part.start - 1 - SELF_CHECK_CONTEXT)
    hi = min(len(pin_lines), (part.end or part.start) + SELF_CHECK_CONTEXT)
    window = "\n".join(pin_lines[lo:hi]).lower()
    if any(token in window for token in tokens):
        return PartResult(part, "ANCHORED", None, None, None, [])
    # A ref that cites loading logic never spells the value out, so its absence
    # here proves nothing. Only finding the value somewhere else in the file
    # shows the ref points at the wrong place.
    elsewhere = sorted(
        {
            index
            for index, line in enumerate(pin_lines, 1)
            for token in tokens
            if token in line.lower()
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


def reconcile_self_check(parts: list[PartResult]) -> list[PartResult]:
    """Judge a self-checked entry whole rather than part by part.

    A ref often cites both the table carrying the value and the code that
    loads the file. Once one part anchors on the value, the others describe
    behaviour and cannot be judged by value: the checker would only rediscover
    the value where the first part already points. A structurally absent part
    still counts, since that verdict does not rest on the value.
    """
    if not any(part.status == "ANCHORED" for part in parts):
        return parts
    kept = ("ANCHORED", "GONE", "EXTERNAL")
    return [
        part if part.status in kept
        else PartResult(part.part, "ANCHORED", None, None, None, [])
        for part in parts
    ]


def version_tag_candidates(core_version: str) -> list[str]:
    """Tag spellings a declared core_version might use."""
    version = str(core_version or "").strip()
    if not version or " " in version:
        return []
    bare = version.lstrip("vV")
    return list(dict.fromkeys([version, f"v{bare}", bare]))


def detect_pinned_tag(
    profile: dict, repo, pin: str, head: str, cache_dir: str, offline: bool
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
    """
    if pin == head:
        return None
    for tag in version_tag_candidates(profile.get("core_version")):
        if upstream.tag_commit(repo, tag, cache_dir, offline) == pin:
            return tag
    return None


def build_report(
    name: str, profile: dict, cache_dir: str, offline: bool = False
) -> ProfileReport:
    """Confront one profile with its upstream."""
    report = ProfileReport(name=name, entries=[], counts={})

    refs = [
        (
            entry.get("name", "") + (f" [{label}]" if label else ""),
            value,
            _anchor_tokens(entry),
        )
        for entry in (profile.get("files") or [])
        if isinstance(entry, dict) and entry.get("source_ref")
        for label, value in source_ref_values(entry.get("source_ref"))
    ]

    if select_repo(profile) is None:
        declared = str(profile.get("source") or profile.get("upstream") or "")
        report.skipped = f"unsupported host: {declared or 'none declared'}"
        return report

    views = select_views(profile, cache_dir, offline)
    if not views:
        report.skipped = (
            "no source_commit and no resolvable profiled_date "
            "on any declared repository"
        )
        return report
    primary = views[0]
    report.repo, report.host = primary.repo.slug, primary.repo.host
    report.repos = [v.repo.slug for v in views]
    report.pin, report.pin_origin = primary.pin, primary.origin
    report.head = primary.head
    report.pinned_tag = detect_pinned_tag(
        profile, primary.repo, primary.pin, primary.head, cache_dir, offline
    )

    # A profile carrying no source_ref still has a pin worth writing and a
    # version worth checking, so the revisions above are resolved first.
    if not refs:
        report.skipped = "no source_ref"
        return report

    owners: dict[str, RepoView] = {}
    context: dict[str, object] = {}

    def _locate(path: str) -> tuple[RepoView, str]:
        """Repository and real path carrying a cited path, HEAD before pin.

        A ref may prefix the path with the repository directory name, as it
        appears in a parent folder holding both clones: 270 parts across 21
        profiles do. That prefix is stripped only as a last resort, once the
        path as written has failed against every repository and revision.
        """
        candidates = [path]
        head, _, tail = path.partition("/")
        if tail and any(head == v.repo.name for v in views):
            candidates.append(tail)
        for candidate in candidates:
            for sha_of in (lambda v: v.head, lambda v: v.pin):
                for view in views:
                    found = upstream.fetch_file(
                        view.repo, sha_of(view), candidate, cache_dir, offline
                    )
                    if found is not None:
                        return view, candidate
        return primary, path

    def resolve_path(path: str) -> tuple[RepoView, str]:
        if path not in owners:
            owners[path] = _locate(path)
        return owners[path]

    def _context_for(view: RepoView):
        key = view.repo.slug
        if key not in context:
            comparison = upstream.compare(
                view.repo, view.pin, view.head, cache_dir, offline
            )
            tree, truncated = upstream.list_tree(
                view.repo, view.head, cache_dir, offline
            )
            context[key] = (comparison, tree)
            if truncated and tree:
                print(
                    f"{name}: {key} HEAD tree truncated by the forge, "
                    "rename search is partial",
                    file=sys.stderr,
                )
        return context[key]

    def rename_getter(path: str) -> tuple[str | None, list[str]]:
        """Resolved only when a cited file has vanished, then memoised.

        Every declared repository is searched, not just the one that owns the
        path: a profile citing both a port and its upstream may point at a file
        that only the other one carries.
        """
        owner, actual = resolve_path(path)
        ordered = [owner] + [v for v in views if v is not owner]
        candidates: list[str] = []
        for view in ordered:
            comparison, tree = _context_for(view)
            found, near = resolve_rename(comparison, actual, tree)
            if found:
                return found, []
            # Only the owning repository reports near misses: pooling them
            # across repositories turns a resolvable path into an ambiguous one.
            if view is owner:
                candidates = near
        return None, candidates

    lines_cache: dict[tuple[str, str], list[str] | None] = {}

    def fetch(which: str, path: str):
        """Lines for one path at one revision, read once per run.

        The same object is handed back every time so the opcode cache can key
        on identity.
        """
        key = (which, path)
        if key not in lines_cache:
            view, actual = resolve_path(path)
            sha = view.pin if which == PIN else view.head
            lines_cache[key] = upstream.fetch_file(
                view.repo, sha, actual, cache_dir, offline
            )
        return lines_cache[key]

    def describe(path: str) -> tuple[str | None, str | None, str]:
        view, actual = resolve_path(path)
        slug = view.repo.slug if view is not primary else None
        return slug, upstream.raw_url(view.repo, view.head, actual), actual

    # Comparing a revision with itself anchors every ref whatever it cites, so
    # a profile already sitting on HEAD is judged on self-consistency instead.
    self_check = bool(report.pinned_tag) or primary.pin == primary.head
    if self_check:
        staged = [
            (entry_name, ref, reconcile_self_check([
                verify_at_pin(part, fetch(PIN, part.path), tokens)
                for part in split_source_ref(ref)
            ]))
            for entry_name, ref, tokens in refs
        ]
    else:
        staged = [
            (entry_name, ref, [
                anchor_part(part, fetch, rename_getter, describe, tokens)
                for part in split_source_ref(ref)
            ])
            for entry_name, ref, tokens in refs
        ]

    shifts = dominant_shifts([p for _, _, parts in staged for p in parts])
    for entry_name, ref, parts in staged:
        parts = [resolve_by_shift(p, shifts) for p in parts]
        status = worst_status([p.status for p in parts])
        report.entries.append(EntryReport(entry_name, ref, status, parts))
        report.counts[status] = report.counts.get(status, 0) + 1

    return report


def _render_span(path: str, start: int | None, end: int | None) -> str:
    if start is None:
        return path
    if end and end != start:
        return f"{path}:{start}-{end}"
    return f"{path}:{start}"


def _original_part(part: PartResult) -> str:
    """The part exactly as the profile writes it today."""
    return part.part.raw or _render_span(
        part.part.path, part.part.start, part.part.end
    )


def _rendered_part(part: PartResult) -> str:
    """The part rewritten onto its new location, annotation preserved."""
    span = _render_span(part.new_path or part.part.path, part.start, part.end)
    raw = part.part.raw
    if not raw:
        return span
    located = _trim_prose(_ANNOTATION_RE.sub("", raw).strip())
    if located and located in raw:
        return raw.replace(located, span, 1)
    return span


def _part_line(part: PartResult) -> str:
    detail = part.status
    if part.new_path:
        detail += f" -> {part.new_path}"
    if part.start is not None and part.status != "ANCHORED":
        span = f"{part.start}"
        if part.end and part.end != part.start:
            span += f"-{part.end}"
        detail += f" -> {span}"
    if part.candidates:
        detail += f"  candidats: {', '.join(str(c) for c in part.candidates)}"
    if part.reason:
        detail += f"  ({part.reason})"
    if part.repo:
        detail += f"  [{part.repo}]"
    return f"      {_original_part(part)}  {detail}"


def format_report(report: ProfileReport, changed_only: bool = False) -> str:
    """Human-readable report for one profile."""
    slugs = " + ".join(report.repos) if report.repos else (report.repo or "")
    lines = [f"{report.name}  {slugs}".rstrip()]
    if report.pin and report.head:
        lines.append(
            f"  {report.pin[:7]} -> {report.head[:7]}   pin: {report.pin_origin}"
        )
    if report.pinned_tag:
        lines.append(
            f"  pinned to tag {report.pinned_tag}: checked against its own "
            "revision, not against HEAD"
        )
    elif report.pin and report.pin == report.head:
        lines.append("  pin is HEAD: checked for self-consistency")
    if report.skipped:
        lines.append(f"  skipped: {report.skipped}")
        return "\n".join(lines)
    for entry in report.entries:
        if changed_only and entry.status not in REVIEW_STATUSES:
            continue
        lines.append(f"  {entry.name}  {entry.source_ref}")
        for part in entry.parts:
            lines.append(_part_line(part))
    summary = ", ".join(
        f"{count} {status.lower()}" for status, count in sorted(report.counts.items())
    )
    lines.append(f"  {len(report.entries)} refs: {summary}")
    lines.append(f"  {report.needs_review()} demandent une relecture")
    return "\n".join(lines)


def report_to_dict(report: ProfileReport) -> dict:
    """Serialisable form of one report."""
    payload = asdict(report)
    payload["needs_review"] = report.needs_review()
    return payload


def format_markdown(reports: list[ProfileReport]) -> str:
    """Report set as a markdown document."""
    lines = [
        "# profile-sync",
        "",
        "| profil | depot | refs | relecture |",
        "|---|---|---|---|",
    ]
    for report in reports:
        if report.skipped:
            lines.append(
                f"| {report.name} | {report.repo or ''} | skipped | {report.skipped} |"
            )
            continue
        lines.append(
            f"| {report.name} | {report.repo} | {len(report.entries)} "
            f"| {report.needs_review()} |"
        )
    for report in reports:
        lines.extend(["", "```", format_report(report), "```"])
    return "\n".join(lines)


def fetch_plan(report: ProfileReport) -> list[str]:
    """Raw URLs at HEAD for the refs that need the code read again."""
    if report.skipped or not report.head or not report.host:
        return []
    owner, _, name = (report.repo or "").partition("/")
    fallback = upstream.make_repo(report.host, owner, name)
    urls = []
    for entry in report.entries:
        if entry.status not in REVIEW_STATUSES:
            continue
        for part in entry.parts:
            url = part.head_url
            if url is None:
                if fallback is None:
                    continue
                path = part.new_path or part.part.path
                url = upstream.raw_url(fallback, report.head, path)
            if part.part.start:
                url += f"#L{part.part.start}"
            urls.append(url)
    return urls


@dataclass(frozen=True)
class VersionReport:
    declared: str
    latest_tag: str | None
    latest_release: str | None
    release_date: str | None
    tag_matches_declared: bool
    tag_commit: str | None


def check_version(
    profile: dict, repo, cache_dir: str, offline: bool
) -> VersionReport | None:
    """Declared core_version against the latest upstream tag and release."""
    declared = str(profile.get("core_version") or "")
    if not declared:
        return None
    tags = upstream.list_tags(repo, cache_dir, offline)
    release = upstream.latest_release(repo, cache_dir, offline)
    matches = declared in tags
    commit = (
        upstream.resolve_tag_commit(repo, declared, cache_dir, offline)
        if matches
        else None
    )
    return VersionReport(
        declared,
        tags[0] if tags else None,
        release.tag if release else None,
        release.date if release else None,
        matches,
        commit,
    )


def version_warning(report: VersionReport | None, pin: str | None) -> str | None:
    """Flag a declared version that names a tag away from the resolved pin."""
    if report is None or not report.tag_commit or not pin:
        return None
    if report.tag_commit == pin:
        return None
    return (
        f"core_version {report.declared} names tag commit {report.tag_commit[:7]}, "
        f"the pin resolved to {pin[:7]}"
    )


FILE_EXTENSIONS = (
    "bin", "rom", "zip", "dat", "bios", "img", "chd", "nvram", "sav",
    "ips", "pal", "fnt",
)

_FILE_RE = re.compile(
    r"[\w./+-]+\.(?:" + "|".join(FILE_EXTENSIONS) + r")\b", re.IGNORECASE
)
_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_CRC_RE = re.compile(r"\b(?:0x)?([0-9a-fA-F]{8})\b")


def declared_names(profile: dict) -> set[str]:
    """Every filename the profile covers, aliases included."""
    names = set()
    for entry in profile.get("files") or []:
        if not isinstance(entry, dict):
            continue
        for value in [entry.get("name", "")] + list(entry.get("aliases") or []):
            if value:
                names.add(os.path.basename(str(value)).casefold())
    return names


def declared_hashes(profile: dict) -> set[str]:
    """Every hash the profile declares."""
    hashes = set()
    for entry in profile.get("files") or []:
        if isinstance(entry, dict):
            hashes.update(collect_tokens(entry))
    return hashes


def detect_new_files(
    head_lines: list[str], known: set[str], cap: int = 25
) -> tuple[list[tuple[int, str]], int]:
    """Filename literals at HEAD the profile does not declare."""
    found: list[tuple[int, str]] = []
    seen: set[str] = set()
    elided = 0
    for number, line in enumerate(head_lines, start=1):
        for match in _FILE_RE.findall(line):
            name = os.path.basename(match).casefold()
            if name in known or name in seen:
                continue
            seen.add(name)
            if len(found) >= cap:
                elided += 1
                continue
            found.append((number, os.path.basename(match)))
    return found, elided


def watch_hashes(added_lines: list[str], known: set[str]) -> list[tuple[str, str]]:
    """Hash literals in added lines that no profile entry declares."""
    found: list[tuple[str, str]] = []
    for line in added_lines:
        strong = bool(_SHA1_RE.search(line) or _MD5_RE.search(line))
        for pattern, kind in ((_SHA1_RE, "sha1"), (_MD5_RE, "md5")):
            for value in pattern.findall(line):
                if value.lower() not in known:
                    found.append((kind, value.lower()))
        if strong or not _FILE_RE.search(line):
            continue
        for value in _CRC_RE.findall(line):
            if value.lower() not in known:
                found.append(("crc32", value.lower()))
    return found


def unified_for_path(
    pin_lines: list[str], head_lines: list[str], path: str, context: int
) -> str:
    """Unified diff of one cited file between the two revisions."""
    diff = difflib.unified_diff(
        pin_lines,
        head_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        n=context,
        lineterm="",
    )
    return "\n".join(diff)


def tree_diff(result: CompareResult, ref_dirs: set[str]) -> list[str]:
    """Tree changes restricted to the directories the refs point at."""
    lines = []
    for change in result.files:
        directory = posixpath.dirname(change.path)
        if ref_dirs and not any(
            directory == d or directory.startswith(d + "/") for d in ref_dirs
        ):
            continue
        if change.status == "renamed" and change.previous_path:
            lines.append(f"renamed  {change.previous_path} -> {change.path}")
        else:
            lines.append(f"{change.status}  {change.path}")
    if result.truncated:
        lines.append("comparison truncated by the forge, list is partial")
    return lines


DRIFT_WEIGHTS = {"GONE": 40, "CHANGED": 30, "AMBIGUOUS": 15, "SHIFTED": 1}


def drift_score(
    report: ProfileReport, version: VersionReport | None, commits: int
) -> int:
    """Rank profiles by how far they have drifted from their pin."""
    counts = report.counts or {}
    score = sum(DRIFT_WEIGHTS.get(k, 0) * v for k, v in counts.items())
    if version is not None and not version.tag_matches_declared:
        if version.latest_release and version.latest_release != version.declared:
            score += 10
    score += min(commits, 20) // 4
    return score


class YamlWriteError(Exception):
    """A profile edit did not land exactly as intended."""


def _top_level_indices(lines: list[str], key: str) -> list[int]:
    """Indices of lines declaring a key at the top level of the document."""
    prefix = f"{key}:"
    return [i for i, line in enumerate(lines) if line.startswith(prefix)]


def insert_after_line(text: str, key: str, new_line: str) -> str:
    """Insert a line right after a top-level key."""
    lines = text.splitlines()
    indices = _top_level_indices(lines, key)
    if len(indices) != 1:
        raise YamlWriteError(
            f"{key}: expected one top-level line, found {len(indices)}"
        )
    lines.insert(indices[0] + 1, new_line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def _field_value(line: str) -> str:
    return line.split(":", 1)[1].strip().strip('"').strip("'")


def find_field_line(text: str, key: str, expected: str, start: int = 0) -> int:
    """Index of the first `key:` line at or after `start` holding `expected`.

    Positional counting is not safe here: `source_ref` also appears outside
    `files:` in some profiles, under `data_directories:` for instance, which
    shifts every ordinal past it.
    """
    lines = text.splitlines()
    marker = f"{key}:"
    for index in range(start, len(lines)):
        line = lines[index]
        if line.strip().startswith(marker) and _field_value(line) == expected:
            return index
    raise YamlWriteError(
        f"{key}: no line holding {expected!r} at or after line {start + 1}"
    )


def replace_field_line(text: str, key: str, expected: str, value: str,
                       start: int = 0) -> tuple[str, int]:
    """Rewrite the first `key:` line holding `expected`. Returns text and index."""
    index = find_field_line(text, key, expected, start)
    lines = text.splitlines()
    line = lines[index]
    indent = line[: len(line) - len(line.lstrip())]
    lines[index] = f'{indent}{key}: "{value}"'
    joined = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    return joined, index


def apply_edit(path: Path, new_text: str, expected: dict) -> None:
    """Write, then verify the parsed document matches what was intended."""
    original = path.read_text(encoding="utf-8")
    path.write_text(new_text, encoding="utf-8")
    try:
        written = yaml.safe_load(new_text)
    except yaml.YAMLError as exc:
        path.write_text(original, encoding="utf-8")
        raise YamlWriteError(f"{path}: parse failed after write: {exc}") from exc
    if written != expected:
        path.write_text(original, encoding="utf-8")
        raise YamlWriteError(f"{path}: structure changed beyond the intended field")


def backfill_commit(path: Path, sha: str) -> bool:
    """Insert source_commit after profiled_date. False when already present."""
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    if document.get("source_commit"):
        return False
    new_text = insert_after_line(text, "profiled_date", f'source_commit: "{sha}"')
    expected = dict(document)
    expected["source_commit"] = sha
    apply_edit(path, new_text, expected)
    return True


def _is_rewritable(ref: str) -> bool:
    """Every ref whose parts can be put back with their prose intact."""
    parts = split_source_ref(ref)
    if not parts:
        return False
    return ", ".join(p.raw for p in parts) == ", ".join(
        chunk for chunk in split_outside_parentheses(ref)
    )


def rebase_refs(
    path: Path, report: ProfileReport, accept_changed: bool = False
) -> list[str]:
    """Recale the line ranges of parts whose content is unchanged.

    All or nothing per profile. `source_commit` names the revision the refs
    are written against, so moving some refs to HEAD while others still
    describe the pinned revision would leave the profile self-contradictory,
    and the next comparison would read the pinned revision at line numbers
    that only make sense at HEAD.
    """
    if report.pinned_tag:
        return []
    statuses = REBASE_STATUSES + (("CHANGED",) if accept_changed else ())
    blocking = [s for s in REVIEW_STATUSES if s not in statuses]
    if any((report.counts or {}).get(s) for s in blocking):
        return []
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    carriers = [
        entry
        for entry in (document.get("files") or [])
        if isinstance(entry, dict) and entry.get("source_ref")
    ]
    applied: list[str] = []
    cursor = 0

    for position, entry in enumerate(report.entries):
        if not _is_rewritable(entry.source_ref) or entry.name.endswith("]"):
            # Rewriting would drop the author's annotations, or the refs live
            # under a mode key rather than on a source_ref line.
            continue
        rendered = []
        touched = False
        for part in entry.parts:
            if part.status in statuses and part.start is not None:
                recaled = _rendered_part(part)
                if recaled != _original_part(part):
                    touched = True
                rendered.append(recaled)
            else:
                rendered.append(_original_part(part))
        if not touched:
            # Still consume this entry's line so a later entry carrying the
            # same ref cannot match it.
            cursor = find_field_line(text, "source_ref", entry.source_ref, cursor) + 1
            continue
        new_ref = ", ".join(rendered)
        text, index = replace_field_line(
            text, "source_ref", entry.source_ref, new_ref, cursor
        )
        cursor = index + 1
        carriers[position]["source_ref"] = new_ref
        applied.append(f"{entry.source_ref} -> {new_ref}")

    if applied:
        apply_edit(path, text, document)
    return applied


def pending_recale(report: ProfileReport, accept_changed: bool = False) -> int:
    """Parts that ought to move but sit in a ref the writer will not touch.

    An annotated ref cannot be regenerated without losing its prose, so its
    parts stay on the pinned line numbers. Advancing the pin while they do
    would leave the profile describing two revisions at once.
    """
    movable = REBASE_STATUSES + (("CHANGED",) if accept_changed else ())
    pending = 0
    for entry in report.entries or []:
        if _is_rewritable(entry.source_ref) and not entry.name.endswith("]"):
            continue
        pending += sum(
            1
            for part in entry.parts
            if part.status in movable
            and part.start is not None
            and _rendered_part(part) != _original_part(part)
        )
    return pending


def bump_commit(
    path: Path, report: ProfileReport, accept_changed: bool = False
) -> bool:
    """Advance source_commit to HEAD when nothing needs a read again."""
    if report.skipped or not report.head or report.pinned_tag:
        return False
    blocking = REVIEW_STATUSES if not accept_changed else (
        s for s in REVIEW_STATUSES if s != "CHANGED"
    )
    if any((report.counts or {}).get(s) for s in blocking):
        return False
    if pending_recale(report, accept_changed):
        return False
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    expected = dict(document)
    expected["source_commit"] = report.head
    if document.get("source_commit"):
        new_text, _ = replace_field_line(
            text, "source_commit", str(document["source_commit"]), report.head
        )
    else:
        new_text = insert_after_line(
            text, "profiled_date", f'source_commit: "{report.head}"'
        )
    apply_edit(path, new_text, expected)
    return True


def emulators_dir_is_dirty(emulators_dir: str) -> bool:
    """True when the profile directory carries uncommitted changes."""
    result = subprocess.run(
        ["git", "status", "--porcelain", "--", emulators_dir],
        capture_output=True,
        text=True,
        check=False,
    )
    return bool(result.stdout.strip())


def build_parser() -> argparse.ArgumentParser:
    """Command line: selection, output, detection, writes, network."""
    parser = argparse.ArgumentParser(
        description="Confront emulator profiles with their upstream source"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--emulator", help="a single profile")
    group.add_argument("--all", action="store_true", help="every profile")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--system", help="keep profiles covering this system")
    parser.add_argument("--type", dest="type_", help="keep profiles of this type")
    parser.add_argument("--stale-before", help="keep profiles profiled before a date")
    parser.add_argument("--limit", type=int, help="stop after N profiles")
    parser.add_argument("--changed-only", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--fetch-plan", action="store_true")
    parser.add_argument("--full-diff", action="store_true")
    parser.add_argument("--ref", help="restrict --full-diff to one cited path")
    parser.add_argument("--context", type=int, default=3)
    parser.add_argument("--check-version", action="store_true")
    parser.add_argument("--detect-new-files", action="store_true")
    parser.add_argument("--watch-hashes", action="store_true")
    parser.add_argument("--tree-diff", action="store_true")
    parser.add_argument("--triage", action="store_true")
    parser.add_argument("--backfill-commits", action="store_true")
    parser.add_argument("--rebase-refs", action="store_true")
    parser.add_argument("--bump-commit", action="store_true")
    parser.add_argument(
        "--accept-changed",
        action="store_true",
        help="recale CHANGED refs too, after their diff has been read",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE)
    return parser


def select_profiles(profiles: dict, args) -> dict:
    """Profiles matching the selection flags."""
    if args.emulator:
        if args.emulator not in profiles:
            print(f"unknown profile: {args.emulator}", file=sys.stderr)
            raise SystemExit(1)
        return {args.emulator: profiles[args.emulator]}

    selected = {}
    for name, profile in sorted(profiles.items()):
        if profile.get("type") in ("alias", "test"):
            continue
        if args.system and args.system not in (profile.get("systems") or []):
            continue
        if args.type_ and profile.get("type") != args.type_:
            continue
        if args.stale_before:
            profiled = str(profile.get("profiled_date") or "")
            if not profiled or profiled >= args.stale_before:
                continue
        selected[name] = profile
        if args.limit and len(selected) >= args.limit:
            break
    return selected


def _check_quota(count: int, offline: bool) -> None:
    """Refuse a run the anonymous quota cannot carry to completion."""
    if offline or os.environ.get("GITHUB_TOKEN"):
        return
    if count * 4 > ANON_QUOTA:
        print(
            f"{count} profiles need roughly {count * 4} API calls, the anonymous "
            f"quota is {ANON_QUOTA} per hour. Set GITHUB_TOKEN or use --offline.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _apply_writes(args, name: str, profile: dict, report: ProfileReport) -> None:
    path = Path(args.emulators_dir) / f"{name}.yml"
    if not path.is_file():
        return
    if args.backfill_commits and report.pin and not profile.get("source_commit"):
        if args.dry_run:
            print(f"{name}: would write source_commit {report.pin[:7]}")
        elif backfill_commit(path, report.pin):
            print(f"{name}: source_commit {report.pin[:7]}")
    if args.rebase_refs and not args.dry_run and not report.skipped:
        for line in rebase_refs(path, report, args.accept_changed):
            print(f"{name}: {line}")
    if (
        args.bump_commit
        and not args.dry_run
        and bump_commit(path, report, args.accept_changed)
    ):
        print(f"{name}: source_commit -> {report.head[:7]}")


def _cited_paths(report: ProfileReport) -> list[str]:
    return sorted(
        {part.new_path or part.part.path for e in report.entries for part in e.parts}
    )


def _print_version(args, profile: dict, report: ProfileReport, repo) -> None:
    version = check_version(profile, repo, args.cache_dir, args.offline)
    if version is None:
        return
    print(
        f"  version: declared {version.declared}, "
        f"latest tag {version.latest_tag}, "
        f"latest release {version.latest_release} ({version.release_date})"
    )
    warning = version_warning(version, report.pin)
    if warning:
        print(f"  {warning}")


def _print_detection(args, profile: dict, report: ProfileReport, repo) -> None:
    names, hashes = declared_names(profile), declared_hashes(profile)
    for path in _cited_paths(report):
        head_lines = upstream.fetch_file(
            repo, report.head, path, args.cache_dir, args.offline
        )
        if head_lines is None:
            continue
        if args.detect_new_files:
            found, elided = detect_new_files(head_lines, names)
            for number, name in found:
                print(f"  new file: {path}:{number}  {name}")
            if elided:
                print(f"  new file: {elided} further matches not shown")
        if args.watch_hashes:
            pin_lines = (
                upstream.fetch_file(
                    repo, report.pin, path, args.cache_dir, args.offline
                )
                or []
            )
            added = [
                line
                for line in difflib.unified_diff(pin_lines, head_lines, n=0)
                if line.startswith("+") and not line.startswith("+++")
            ]
            for kind, value in watch_hashes(added, hashes):
                print(f"  new {kind}: {path}  {value}")


def _print_extras(args, profile: dict, report: ProfileReport) -> None:
    """Optional per-profile sections beyond the ref report."""
    wants = (
        args.check_version
        or args.detect_new_files
        or args.watch_hashes
        or args.full_diff
        or args.tree_diff
    )
    if not wants or not report.head:
        return
    repo = select_repo(profile)
    if repo is None:
        return

    if args.check_version:
        _print_version(args, profile, report, repo)
    if args.detect_new_files or args.watch_hashes:
        _print_detection(args, profile, report, repo)
    if args.full_diff:
        for path in _cited_paths(report):
            if args.ref and args.ref not in path:
                continue
            pin_lines = (
                upstream.fetch_file(
                    repo, report.pin, path, args.cache_dir, args.offline
                )
                or []
            )
            head_lines = (
                upstream.fetch_file(
                    repo, report.head, path, args.cache_dir, args.offline
                )
                or []
            )
            text = unified_for_path(pin_lines, head_lines, path, args.context)
            if text:
                print(text)
    if args.tree_diff:
        comparison = upstream.compare(
            repo, report.pin, report.head, args.cache_dir, args.offline
        )
        # The repository root is a directory like any other: dropping the
        # empty dirname would turn the filter off and list the whole tree.
        ref_dirs = {posixpath.dirname(p) for p in _cited_paths(report)}
        for line in tree_diff(comparison, ref_dirs):
            print(f"  {line}")


def _print_triage(args, selected: dict, reports: list[ProfileReport]) -> None:
    """Profiles ranked by drift, worst first."""
    ranked = []
    for report in reports:
        profile = selected[report.name]
        version = None
        commits = 0
        repo = select_repo(profile)
        if report.head and repo is not None:
            version = check_version(profile, repo, args.cache_dir, args.offline)
            paths = _cited_paths(report)
            for path in paths[:TRIAGE_PATH_SAMPLE]:
                commits += upstream.commits_touching(
                    repo, path, report.pin, args.cache_dir, args.offline
                )
            if len(paths) > TRIAGE_PATH_SAMPLE:
                print(
                    f"{report.name}: commit count sampled on "
                    f"{TRIAGE_PATH_SAMPLE} of {len(paths)} paths",
                    file=sys.stderr,
                )
        ranked.append((drift_score(report, version, commits), report))
    for score, report in sorted(ranked, key=lambda item: -item[0]):
        state = report.skipped or f"{report.needs_review()} to review"
        print(f"{score:5d}  {report.name:30s}  {state}")


def main() -> None:
    """Build one report per selected profile, then apply writes and output."""
    args = build_parser().parse_args()
    if args.accept_changed and not args.emulator:
        print(
            "--accept-changed applies to one profile at a time: its diff has "
            "to be read before its CHANGED refs can be recaled.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    selected = select_profiles(profiles, args)
    _check_quota(len(selected), args.offline)

    writes = args.backfill_commits or args.rebase_refs or args.bump_commit
    if (
        writes
        and not args.dry_run
        and not args.force
        and emulators_dir_is_dirty(args.emulators_dir)
    ):
        print(
            f"{args.emulators_dir} carries uncommitted changes. "
            "Commit them first or pass --force.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    reports = []
    for name, profile in selected.items():
        try:
            report = build_report(name, profile, args.cache_dir, args.offline)
        except upstream.RateLimitError:
            raise
        except upstream.UpstreamError as exc:
            # One unreachable forge must not abandon the other profiles.
            print(f"{name}: {exc}", file=sys.stderr)
            report = ProfileReport(
                name=name, entries=[], counts={}, skipped=f"upstream error: {exc}"
            )
        reports.append(report)
        if writes:
            try:
                _apply_writes(args, name, profile, report)
            except YamlWriteError as exc:
                # The guard already left the file untouched; keep going.
                print(f"{name}: write refused: {exc}", file=sys.stderr)

    if args.as_json:
        print(json.dumps([report_to_dict(r) for r in reports], indent=2))
        return
    if args.markdown:
        target = Path("claudedocs") / f"profile-sync-{date.today().isoformat()}.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(format_markdown(reports), encoding="utf-8")
        print(f"written: {target}")
        return
    if args.fetch_plan:
        for report in reports:
            for url in fetch_plan(report):
                print(url)
        return
    if args.triage:
        _print_triage(args, selected, reports)
        return
    printed = 0
    for report in reports:
        if args.changed_only and not report.needs_review():
            continue
        printed += 1
        print(format_report(report, args.changed_only))
        _print_extras(args, selected[report.name], report)
        print()
    if args.changed_only:
        _print_elided(reports, printed)


def _print_elided(reports: list[ProfileReport], printed: int) -> None:
    """Account for what --changed-only left out, grouped by reason."""
    reasons: dict[str, int] = {}
    for report in reports:
        if report.needs_review():
            continue
        key = report.skipped or "nothing to review"
        reasons[key] = reasons.get(key, 0) + 1
    if not reasons:
        return
    total = sum(reasons.values())
    print(f"{printed} profils listes, {total} non listes:")
    for reason, count in sorted(reasons.items(), key=lambda item: -item[1]):
        print(f"  {count:4d}  {reason}")


if __name__ == "__main__":
    main()
