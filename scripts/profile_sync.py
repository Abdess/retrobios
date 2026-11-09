#!/usr/bin/env python3
"""Confront emulator profiles with their upstream source.

Anchors every source_ref of a profile against the commit the profile was
written at and against upstream HEAD, separating what is mechanically
recalable from what needs the code read again.
"""

from __future__ import annotations

import argparse
import bisect
import difflib
import functools
import itertools
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, os.path.dirname(__file__))

import upstream
import version_basis
from common import (
    _norm_system_id,
    github_token,
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
    resolve_platform_cores,
    suggest_names,
    system_index,
)
from hashing import parse_hash_list
from sourceref import (  # noqa: F401  (re-exported for callers and tests)  # noqa: F401  (the prose grammar, re-exported)
    _ANNOTATION_RE,
    _BARE_RANGE_RE,
    _LOCATED_RE,
    _PROJECT_WORD_RE,
    _PROSE_LIST_DELIMITERS,
    _REF_RE,
    _SPLIT_RE,
    _BINARY_SUFFIXES,
    _HEX_ADDRESS_RE,
    PROSE_CITE_RE,
    PROSE_CONT_RE,
    PROSE_CONT_SPACED_RE,
    PROSE_EXTENSIONLESS,
    PROSE_LINKING_WORDS,
    PROSE_LIST_ITEM_RE,
    PROSE_WRAPPED_RANGE_RE,
    REPO_ROLES,
    RefPart,
    _prose_external,
    _prose_runs,
    _trim_prose,
    is_binary_citation,
    parse_source_ref,
    ref_prose_text,
    ref_role,
    resolve_project_word,
    source_ref_values,
    split_outside_parentheses,
    split_source_ref,
)
from upstream import CompareResult, find_renamed

DEFAULT_CACHE = upstream.CACHE_DIR
ANON_QUOTA = 60
TRIAGE_PATH_SAMPLE = 5
# A pass that asks the forges says where it is at this interval: an online
# --all --triage ran 15 minutes without a word and read as hung.
PROGRESS_SECONDS = 30

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

PIN = "pin"
HEAD = "head"

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


@dataclass(frozen=True)
class RepoView:
    """One repository a profile cites, at the two revisions under comparison."""

    repo: object
    pin: str
    head: str
    origin: str
    field: str
    # The build mode a keyed source names this repository under (ymir,
    # xenia-edge): `standalone` or `libretro`, empty for a plain URL.
    mode: str = ""


HASH_FIELDS = ("sha1", "md5", "crc32", "sha256", "known_hash_adler32")


def entry_hashes(entry: dict) -> list[str]:
    """Content values an entry declares, its own and its members'.

    An archive entry carries no hash of its own: MAME and FBNeo hash the ROMs
    inside the container, so `contents[]` is where its content values live.
    Ignoring them leaves the archive stem as the only token, and a stem like
    `esh` matches seventy lines of its own driver.
    """
    tokens: list[str] = []
    contents = entry.get("contents")
    members = contents if isinstance(contents, list) else []
    for source in (entry, *members):
        if not isinstance(source, dict):
            continue
        for field in HASH_FIELDS:
            for v in parse_hash_list(source.get(field)):
                if v not in tokens:
                    tokens.append(v)
    return tokens


def collect_tokens(entry: dict) -> list[str]:
    """Values declared by one file entry: hashes, then name as fallback."""
    tokens = entry_hashes(entry)
    if not tokens:
        name = entry.get("name", "")
        if name:
            tokens.append(os.path.basename(name).lower())
    return tokens


_VERSION_NOTE_RE = re.compile(r"\(\s*v?(\d+(?:\.\d+)+)\s*\)")


def cites_another_version(part: RefPart, core_version: object) -> str | None:
    """The version a part's annotation names, when it is not the documented one.

    A profile may cite two programs side by side, `main.cpp:407-411 (v0.0.11)`
    beside its v0.16.0 pin. The annotation was dropped as prose and the part
    compared with the pin, where it fell on unrelated code yet read ANCHORED.
    """
    match = _VERSION_NOTE_RE.search(part.raw or "")
    if not match:
        return None
    declared = core_version.values() if isinstance(core_version, dict) else [core_version]
    documented = {str(v or "").strip().lstrip("vV") for v in declared}
    return None if match.group(1) in documented else match.group(1)


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


_VERSION_WORD_RE = re.compile(r"v?\d+(\.\d+)+[\w.-]*")


def strip_repo_word(
    path: str, known: frozenset[str] | set[str] = frozenset()
) -> str:
    """Drop a leading project word that names a declared repository.

    `BAM_FPloader FPLoader.cpp:45` follows the `munt ROMInfo.cpp` convention,
    but BAM_FPloader is the profile's own source: the path is FPLoader.cpp,
    to be found in that tree, not an out-of-reach citation.
    """
    if " " not in path:
        return path
    role, rest = ref_role(path)
    if role:
        return rest
    head, _, tail = path.partition(" ")
    if head.lower() in known and tail and "/" not in head and "." not in head:
        tail = tail.strip()
        # `ArcadeFlashWeb v1.0.2 flash/flash.html` names the release the file
        # was read from. The version is not part of the path either.
        version, _, rest = tail.partition(" ")
        if rest and _VERSION_WORD_RE.fullmatch(version):
            return rest.strip()
        return tail
    return path


def narrow_by_cited(matches: list[str], cited_dirs: Iterable[str]) -> list[str]:
    """Keep the candidates under the deepest directory the profile cites.

    A bare `version.h` matches BasiliskII/src/include/version.h and
    SheepShaver/src/include/version.h in cebix/macemu. The profile's own
    source_refs all live under SheepShaver/src, which is the tree the prose
    meant. Candidates under no cited directory are kept only when none is.
    """
    best = -1
    kept: list[str] = []
    for match in matches:
        depth = max(
            (d.count("/") + 1 for d in cited_dirs if match.startswith(d + "/")),
            default=-1,
        )
        if depth > best:
            best, kept = depth, [match]
        elif depth == best:
            kept.append(match)
    return kept if best >= 0 else matches


def symlink_target(path: str, lines: list[str] | None) -> str | None:
    """The file a one-line blob points at, when the blob is a symbolic link.

    Git stores a symlink as a blob holding its target, and the raw endpoints
    serve that text: SheepShaver/src/Unix/ether_unix.cpp is the single line
    ../../../BasiliskII/src/Unix/ether_unix.cpp. Anchoring a line number in
    it would report every citation as beyond the end of the file.
    """
    if not lines or len(lines) != 1:
        return None
    target = lines[0].strip()
    if not target or " " in target or "/" not in target:
        return None
    if posixpath.basename(target) != posixpath.basename(path):
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    return None if resolved.startswith("..") or resolved == path else resolved


def _anchor_tokens(entry: dict) -> list[str]:
    """Values worth searching for when a cited line misses its subject.

    Both the content values and the set name are searched, because profiles
    cite two different shapes. FBNeo and Hypseus refs point at the ROM table,
    where the CRC32s are, while MAME refs point at the machine declaration, which
    carries the set name and no hash at all.
    """
    tokens = collect_tokens(entry)
    name = os.path.basename(str(entry.get("name", ""))).lower()
    stem = name.rsplit(".", 1)[0]
    if stem and stem not in tokens and len(stem) > 2:
        tokens.append(stem)
    return tokens


@dataclass(frozen=True)
class Citation:
    """One citation carried by a profile, wherever it is written.

    A structured citation lives under a source_ref key and keeps its entry
    for the values it declares. A prose citation is a path:line run found
    inside any other string scalar. Its spans locate the path and every
    range token inside the scalar line, so a recale can move the numbers
    and leave the sentence around them alone.
    """

    field: str
    kind: str
    ref: str
    entry: dict | None = None
    holder: object = None
    key: object = None
    label: str = ""
    line: int = 0
    path_span: tuple[int, int] = (0, 0)
    spans: tuple = ()
    parts: tuple = ()
    # Broken across two lines of a literal block. joined_at is where the
    # second line starts in the joined run line, so each span goes back to
    # the line that holds it.
    wrapped: bool = False
    joined_at: int = 0
    # Written in a YAML comment, which the loaded document drops. line is
    # then the physical line of the file and the spans index it.
    in_comment: bool = False


def _list_segments(items: list) -> list[object]:
    """The field path segment naming each list item.

    A name keys its entry. supermodel declares Games.xml twice, once per
    build mode, and both notes answered to files[Games.xml].note: the
    history read one note's citations against the other's text. A repeated
    name takes its build mode, or its index when the mode repeats too.
    """
    keys: list[tuple[str | None, str | None]] = []
    for item in items:
        name = item.get("name") if isinstance(item, dict) else None
        mode = item.get("mode") if isinstance(item, dict) else None
        keys.append((
            None if name is None else str(name),
            mode if isinstance(mode, str) else None,
        ))
    names = Counter(name for name, _ in keys if name is not None)
    modes = Counter(key for key in keys if key[0] is not None)
    segments: list[object] = []
    for index, (name, mode) in enumerate(keys):
        if name is None:
            segments.append(index)
        elif names[name] == 1:
            segments.append(name)
        elif mode and modes[(name, mode)] == 1:
            segments.append(f"{name}@{mode}")
        else:
            segments.append(f"{name}#{index}")
    return segments


def _walk_document(
    node: object, where: str = ""
) -> Iterator[tuple[str, str, dict | list, object, Any]]:
    """Every citation carrier of the document, with its holder and field path.

    Yields ("ref", field, holder, key, value) for each source_ref key and
    ("str", field, holder, key, value) for every other string scalar. One
    walker builds every field path, so the paths that name a scalar today
    still name it when another pass looks it up at another revision.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            spot = f"{where}.{key}" if where else str(key)
            if key == "source_ref":
                yield "ref", spot, node, key, value
            elif isinstance(value, str):
                yield "str", spot, node, key, value
            else:
                yield from _walk_document(value, spot)
    elif isinstance(node, list):
        segments = _list_segments(node)
        for index, item in enumerate(node):
            spot = f"{where}[{segments[index]}]"
            if isinstance(item, str):
                yield "str", spot, node, index, item
            else:
                yield from _walk_document(item, spot)


def _scalar_spans(node: yaml.Node, spans: list[tuple[int, int]]) -> None:
    if isinstance(node, yaml.ScalarNode):
        spans.append((node.start_mark.index, node.end_mark.index))
    elif isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            _scalar_spans(key, spans)
            _scalar_spans(value, spans)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _scalar_spans(item, spans)


def comment_citations(
    text: str, known: frozenset[str] | set[str] = frozenset()
) -> list[Citation]:
    """Citation runs written in the YAML comments of a profile.

    The loader drops comments, so a pin moved without them: zesarux cites
    src/start.c:4870-4874 in a comment written under a revision where those
    lines now hold the --chroma81 branch. A `#` inside a scalar, quoted or in
    a block, is content and not a comment.
    """
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return []
    spans: list[tuple[int, int]] = []
    if root is not None:
        _scalar_spans(root, spans)
    spans.sort()
    starts = [lo for lo, _ in spans]

    def inside_scalar(index: int) -> bool:
        at = bisect.bisect_right(starts, index) - 1
        return at >= 0 and spans[at][0] <= index < spans[at][1]

    citations: list[Citation] = []
    offset = 0
    for number, line in enumerate(text.splitlines(keepends=True)):
        for column, char in enumerate(line):
            if char != "#" or (column and not line[column - 1].isspace()):
                continue
            if inside_scalar(offset + column):
                continue
            comment = line[column + 1:].rstrip("\r\n")
            shift = column + 1
            for _, path_span, run_spans, parts, run, _ in _prose_runs(comment, known):
                citations.append(Citation(
                    field=f"comment line {number + 1}", kind="prose", ref=run,
                    line=number,
                    path_span=(path_span[0] + shift, path_span[1] + shift),
                    spans=tuple((lo + shift, hi + shift) for lo, hi in run_spans),
                    parts=parts, in_comment=True,
                ))
            break
        offset += len(line)
    return citations


def collect_citations(document: dict, text: str | None = None) -> list[Citation]:
    """Every citation the document carries, in document order.

    A source_ref key anywhere in the document is a structured citation:
    files[] holds most of them, data_directories[] carries some too. Every
    other string scalar is scanned for prose runs. A citation is a property
    of the text, not of a field name: anything this walk misses is a
    location profile_sync cannot keep honest.
    """
    known = frozenset(
        repo.name.lower()
        for _, _, url in declared_repositories(document)
        if (repo := upstream.parse_repo(url)) is not None
    )
    citations: list[Citation] = []
    for kind, field, holder, key, value in _walk_document(document):
        if kind == "ref":
            for label, ref in source_ref_values(value):
                citations.append(Citation(
                    field=field, kind="ref", ref=ref, entry=holder,
                    holder=holder, key=key, label=label,
                ))
            if isinstance(value, str):
                for line, path_span, spans, parts, run, joined_at in _prose_runs(
                    ref_prose_text(value), known
                ):
                    citations.append(Citation(
                        field=field, kind="prose", ref=run, holder=holder,
                        key=key, line=line, path_span=path_span, spans=spans,
                        parts=parts, wrapped=bool(joined_at), joined_at=joined_at,
                    ))
            continue
        for line, path_span, spans, parts, run, joined_at in _prose_runs(
            value, known
        ):
            citations.append(Citation(
                field=field, kind="prose", ref=run, holder=holder, key=key,
                line=line, path_span=path_span, spans=spans, parts=parts,
                wrapped=bool(joined_at), joined_at=joined_at,
            ))
    if text is not None:
        citations.extend(comment_citations(text, known))
    return citations


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
    hits = []
    for i in range(len(haystack) - size + 1):
        if haystack[i] == first and haystack[i : i + size] == needle:
            hits.append(i)
    return hits


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
    if pin_lines is None:
        # Present at HEAD, absent at the pin, and the cited range fits the
        # HEAD file: the ref was written against HEAD while source_commit
        # still names an older revision. Saying "missing" sends the reader
        # hunting for a move that never happened: the fix is the pin.
        reason = "pin revision missing"
        if _written_against_head(part, head_lines):
            reason = "written against HEAD, pin names an older revision"
        return PartResult(part, "GONE", None, None, None, [], reason, slug, url)

    end = part.last
    if end > len(pin_lines):
        # The file is there and the line is not yet: the pinned revision is
        # shorter than the one the ref was written against. nestopia cited
        # the palette and database loads at 2041 and 2063, which is where
        # HEAD carries them, over a pin four hundred lines shorter. A range
        # that only ends past the file is no better: dolphin cited 239-323 in
        # a 317-line NANDImporter.cpp, and the block found above the end
        # anchored it.
        reason = (
            "written against HEAD, pin names an older revision"
            if _written_against_head(part, head_lines)
            else "cited range ends past the end of the file"
        )
        return PartResult(part, "GONE", None, None, None, [], reason, slug, url)

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
        if part.status in REBASE_STATUSES and target != own and target in cited:
            part = replace(
                part, status="AMBIGUOUS", candidates=[part.start],
                reason="lands on a line another part of this ref already cites",
            )
        held.append(part)
    return held


@dataclass
class EntryReport:
    name: str
    source_ref: str
    status: str
    parts: list[PartResult]
    kind: str = "ref"
    field: str = ""


@dataclass
class ProfileReport:
    name: str
    repo: str | None = None
    repos: list[str] = field(default_factory=list)
    pinned_tag: str | None = None
    # Set when pinned_tag carries a pin_frozen reason rather than a tag name.
    pin_frozen: bool = False
    host: str | None = None
    pin: str | None = None
    pin_origin: str | None = None
    head: str | None = None
    entries: list[EntryReport] = field(default_factory=list)
    skipped: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    # Declared repositories whose forge the tool cannot read. They are named
    # rather than dropped: a `source` on an unknown host used to fall back to
    # `upstream` in silence, and a divergence between the two went unseen.
    unread: list[str] = field(default_factory=list)
    # The upstream view when the profile declares one: its pin and HEAD. A
    # recale moves its parts onto upstream HEAD lines, so a bump advances
    # upstream_commit with source_commit, or the profile describes two
    # revisions at once (geolith jg.c drifted 213 -> 221 -> 229).
    upstream_pin: str | None = None
    upstream_head: str | None = None
    upstream_origin: str | None = None
    # The release tag the upstream view is pinned on, when it is one. That
    # view is read at its tag, and a bump leaves upstream_commit there.
    upstream_tag: str | None = None
    # Repositories whose pin is no ancestor of the branch the profile
    # tracks: history was rewritten, or the pin lies on another branch.
    orphaned: list[str] = field(default_factory=list)
    # Repositories the forge answers under another owner/name: renamed or
    # transferred. The redirect is followed in silence, so the move is named
    # and counted as review work, since a renamed project is re-profiled.
    moved_repos: list[str] = field(default_factory=list)
    # A profile off any forge names the page announcing its releases
    # (version_source): the version read there, beside the one declared.
    declared_version: str | None = None
    page_version: str | None = None
    # An announced version searched for and found only rebuilt or re-signed.
    no_genuine_copy: str | None = None
    # What realign_prose has to settle before a recale or a bump can run:
    # prose written under an older pin. None when not looked at. Counted to
    # review, or the triage read "0 to review" on a profile whose pin could
    # not move (blastem, xenia-edge, lindbergh-loader).
    stale_prose: list[str] | None = None
    # --check-version on a forge: core_version against the latest tag and
    # release, kept on the report so every output carries it.
    version: VersionReport | None = None
    version_warning: str | None = None
    # --detect-new-files and --watch-hashes, kept on the report so --json
    # carries them to check_freshness. None when not asked. A new file is
    # {path, line, name, since_pin}: since_pin when the pinned revision of
    # the same file does not carry the name. A new hash is {path, kind, value}.
    new_files: list[dict] | None = None
    new_files_elided: dict[str, int] = field(default_factory=dict)
    new_hashes: list[dict] | None = None
    detection_skipped: str | None = None

    # Skips that say the profile cannot be checked as written: a repository
    # that no longer answers, no pin to read, a death the forge contradicts.
    # --strict passed them, and the CI job meant to stop an unchecked profile
    # let a mistyped repository through.
    UNCHECKABLE = (
        "no declared repository answers",
        "no source_commit and no resolvable profiled_date",
        "upstream_gone is declared but the forge answers",
        "upstream gone:",
    )

    def uncheckable(self) -> bool:
        """Whether the skip is a defect of the profile rather than its nature."""
        return bool(self.skipped) and self.skipped.startswith(self.UNCHECKABLE)

    def needs_review(self) -> int:
        counts = self.counts or {}
        return (
            sum(counts.get(status, 0) for status in REVIEW_STATUSES)
            + len(self.orphaned)
            + len(self.stale_prose or ())
            + len(self.moved_repos)
        )


def triage_state(report: ProfileReport) -> str:
    """One triage line: what to review, the pin to set again named first.

    A pin outside its branch's history or a repository answering under
    another name is fixed before any ref is read: pcem showed as "1 to
    review" for an upstream_commit off the dev branch.
    """
    if report.skipped:
        return report.skipped
    state = f"{report.needs_review()} to review"
    if report.orphaned:
        state += f", {len(report.orphaned)} orphaned pin"
    if report.moved_repos:
        state += f", {len(report.moved_repos)} repository moved"
    stale = len(report.stale_prose or ())
    if stale:
        state += f", {stale} prose under an older pin"
    unchecked = (report.counts or {}).get("UNCHECKED", 0)
    if unchecked:
        state += f", {unchecked} unchecked"
    return state


def select_repo(profile: dict) -> upstream.Repo | None:
    """Repository the profile was read from: source first, then upstream.

    A source keyed by build mode with no upstream (uzdoom) names its
    repositories only in the dict, which a plain string read never parses.
    """
    for field in ("source", "upstream"):
        repo = upstream.parse_repo(str(profile.get(field) or ""))
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
) -> tuple[str | None, str | None]:
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
    gone = False
    # A port living on a branch of a fork is absent from the default tip, so
    # the branch it was read from is followed when the profile names one.
    declared = str(profile.get("source_branch") or "") or None
    for field, mode, url in declared_repositories(profile):
        repo = upstream.parse_repo(url)
        if repo is None or (repo.host, repo.slug) in seen:
            continue
        # A mirror carries the source's history, commits and branches alike:
        # its pin is source_commit. It read `source_mirror_commit`, a field
        # no profile carries, and fell back to profiled_date, which a bump
        # never moves (eden judged from f6e76860 while pinned on d16735f5).
        pin_field = "source" if field == "source_mirror" else field
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
            if not pin:
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
        views.append(RepoView(repo, pin, head, origin, field, mode))
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
    for field in ("source", "upstream", "source_mirror"):
        value = profile.get(field)
        if isinstance(value, dict):
            urls.extend((field, str(k), str(v)) for k, v in value.items() if v)
        elif value:
            urls.append((field, "", str(value)))
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


def version_tag_candidates(core_version: str, repo_name: str = "") -> list[str]:
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


def build_report(
    name: str, profile: dict, cache_dir: str, offline: bool = False,
    text: str | None = None,
) -> ProfileReport:
    """Confront one profile with its upstream."""
    report = ProfileReport(name=name, entries=[], counts={})

    # One citation surface for the whole document. A prose citation carries
    # no declared value, so it anchors on content alone: the nudge and
    # relocation heuristics stay off rather than guess from a profile-wide
    # token pool.
    known = frozenset(
        repo.name.lower()
        for _, _, url in declared_repositories(profile)
        if (repo := upstream.parse_repo(url)) is not None
    )
    modes = {mode for _, mode, _ in declared_repositories(profile) if mode}
    refs = []
    for citation in collect_citations(profile, text):
        if citation.kind == "ref":
            entry = citation.entry
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
                display, citation.ref, _anchor_tokens(entry),
                entry_hashes(entry), parts, citation,
            ))
        else:
            refs.append((
                citation.field, citation.ref, [], [],
                list(citation.parts), citation,
            ))
    # A part that names no repository is looked up first where its path is
    # cited elsewhere: a note citing `src/a.c:12` beside source_refs that
    # all read `upstream src/a.c` means that tree.
    # A path cited under both roles lends neither, and such a part is
    # compared in every repository rather than in whichever comes first.
    path_roles = _path_roles(refs)

    def role_of(part: RefPart) -> str:
        if part.role:
            return part.role
        lent = path_roles.get(part.path, ())
        return next(iter(lent)) if len(lent) == 1 else ""

    # Directories the profile already cites, deepest first, to settle a bare
    # filename that several trees of one repository carry.
    cited_dirs: set[str] = set()
    for _, _, _, _, parts, _ in refs:
        for part in parts:
            directory = posixpath.dirname(part.path)
            while directory:
                cited_dirs.add(directory)
                directory = posixpath.dirname(directory)

    report.unread = [
        url
        for _, _, url in declared_repositories(profile)
        if upstream.parse_repo(url) is None
    ]
    if select_repo(profile) is None:
        declared = str(profile.get("source") or profile.get("upstream") or "")
        report.skipped = f"unsupported host: {declared or 'none declared'}"
        return report

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
            return report
        raise
    if stated_gone and any(view.field != "source_mirror" for view in views):
        # Declared dead, yet it answered. A profile that keeps saying so stops
        # being read, so the contradiction is the finding.
        report.skipped = (
            f"upstream_gone is declared but the forge answers: {stated_gone}"
        )
        return report
    if not views and stated_gone:
        report.skipped = f"upstream gone (declared): {stated_gone}"
        return report
    if not views:
        # A declared pin whose repository or branch does not answer is not a
        # profile without a pin: pyxel's kitao/pyxel answers 404, and the
        # message sent the reader looking for a missing source_commit.
        report.skipped = (
            "no declared repository answers (moved, removed, or a branch the "
            "forge does not know)"
            if profile.get("source_commit") or profile.get("upstream_commit")
            else "no source_commit and no resolvable profiled_date "
            "on any declared repository"
        )
        return report
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

    def on_own_revision(view: RepoView) -> bool:
        return view.pin == view.head or (view.repo.host, view.repo.slug) in tagged

    if not report.pinned_tag:
        # A tag or a held pin is off the tracked branch by design.
        report.orphaned = [
            f"{view.repo.slug}: pin {view.pin[:8]} is no ancestor of {view.head[:8]}"
            for view in views
            if not on_own_revision(view)
            and upstream.compare(
                view.repo, view.pin, view.head, cache_dir, offline
            ).diverged
        ]

    # A profile carrying no source_ref still has a pin worth writing and a
    # version worth checking, so the revisions above are resolved first.
    if not refs:
        report.skipped = NO_SOURCE_REF
        return report

    owners: dict[tuple[str, int | None], tuple[RepoView, str]] = {}
    context: dict[str, object] = {}
    truncated_trees: set[str] = set()
    pin_trees: dict[str, list[str] | None] = {}

    def _locate(
        path: str, start: int | None = None, tokens: tuple = (), wanted: str = ""
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
        candidates = [path]
        head, _, tail = path.partition("/")
        if tail and any(head == v.repo.name for v in views):
            candidates.append(tail)
        if "/" not in path:
            # A bare filename, the way prose cites files. Resolved against the
            # pin before HEAD: the ref was written at the pin, and a file that
            # moved since would otherwise be resolved to a HEAD path that does
            # not exist at the pin, reporting GONE for the one reason it never
            # should. The rename search then carries the pin path to HEAD.
            for view in views:
                for tree in (_pin_tree_for(view), _context_for(view)[1]):
                    matches = [
                        p for p in tree or []
                        if posixpath.basename(p) == path
                    ]
                    if len(matches) > 1:
                        matches = narrow_by_cited(matches, cited_dirs)
                    # A few survivors are told apart by the cited line below: a
                    # 266-line Windows configure.ac cannot carry line 754.
                    if len(matches) <= 4:
                        candidates.extend(
                            m for m in matches if m not in candidates
                        )
                    if matches:
                        break
        elif not any(
            fetch_from(v.repo, sha, path) is not None
            for v in views for sha in (v.pin, v.head)
        ):
            # A path written from a subproject directory of a monorepo:
            # `src/main/Main.cc` in emu-ex-plus-alpha is PCE.emu/src/main/Main.cc
            # for one profile and C64.emu/src/main/Main.cc for another. The
            # tree is searched by suffix and the cited directories decide.
            suffix = "/" + path
            for view in views:
                _, tree = _context_for(view)
                matches = [p for p in tree or [] if p.endswith(suffix)]
                if len(matches) > 1:
                    matches = narrow_by_cited(matches, cited_dirs)
                if len(matches) <= 4:
                    candidates.extend(m for m in matches if m not in candidates)

        def score(lines: list[str]) -> int:
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

        # A part that names its repository is looked up there first. In a
        # profile keyed by build mode, a part naming none belongs to the
        # first build declared, as _realign_part decides a shared path: the
        # libretro tree of xenia-edge carries emulator.cc offset, and its
        # better-scored line hid a standalone ref that had moved.
        if not wanted and primary.mode:
            wanted = primary.mode
        ordered = sorted(views, key=lambda v: not _answers(v, wanted)) if wanted else views
        best = None
        for candidate in candidates:
            for sha_of in (lambda v: v.pin, lambda v: v.head):
                for view in ordered:
                    found = fetch_from(view.repo, sha_of(view), candidate)
                    if found is None:
                        continue
                    target = symlink_target(candidate, found)
                    if target:
                        found = fetch_from(view.repo, sha_of(view), target)
                        if found is None:
                            continue
                        candidate = target
                    rank = score(found)
                    if rank and _answers(view, wanted) and view.mode:
                        # An entry of one build mode is that build's code:
                        # xenia-edge's standalone xbox.xex refs scored higher
                        # in the libretro tree, whose same file is offset.
                        return view, candidate
                    if rank == 3 and not wanted and _view_role(view) == "source":
                        # The port carries a copy of the emulator: when the
                        # original holds the same value on the cited line,
                        # the code asking for the file is the emulator's.
                        for other in views:
                            if _view_role(other) != "upstream":
                                continue
                            theirs = fetch_from(other.repo, sha_of(other), candidate)
                            if theirs is not None and score(theirs) == 3:
                                return other, candidate
                    if rank == 3:
                        return view, candidate
                    if best is None or rank > best[0]:
                        best = (rank, view, candidate)
        return (best[1], best[2]) if best else (primary, path)

    def resolve_path(
        path: str, start: int | None = None, tokens: tuple = (), role: str = ""
    ) -> tuple[RepoView, str]:
        key = (path, start, tokens, role)
        if key not in owners:
            owners[key] = _locate(path, start, tokens, role)
        return owners[key]

    def _pin_tree_for(view: RepoView) -> list[str] | None:
        """Tree at the revision the refs were written against, memoised."""
        key = view.repo.slug
        if key not in pin_trees:
            tree, _ = upstream.list_tree(view.repo, view.pin, cache_dir, offline)
            pin_trees[key] = tree
        return pin_trees[key]

    mute: set[tuple[str, str]] = set()

    def fetch_from(repo: upstream.Repo, sha: str, wanted: str) -> list[str] | None:
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
        if key in mute:
            return None
        try:
            found = upstream.fetch_file(repo, sha, wanted, cache_dir, offline)
            if found is None and "/" in wanted:
                # A file of a submodule is read at the commit its gitlink
                # pins in this revision, so a bump moves it with the port.
                inner = upstream.through_gitlink(repo, sha, wanted, cache_dir, offline)
                if inner is not None:
                    found = upstream.fetch_file(*inner, cache_dir, offline)
            return found
        except (upstream.RateLimitError, upstream.NotCachedError):
            raise
        except upstream.UpstreamError as exc:
            mute.add(key)
            print(f"{name}: {repo.host}/{repo.slug} muted, {exc}", file=sys.stderr)
            return None

    def _context_for(view: RepoView) -> tuple[CompareResult, list[str]]:
        key = view.repo.slug
        if key not in context:
            comparison = upstream.compare(
                view.repo, view.pin, view.head, cache_dir, offline
            )
            tree, truncated = upstream.list_tree(
                view.repo, view.head, cache_dir, offline
            )
            context[key] = (comparison, tree)
            if truncated:
                truncated_trees.add(key)
            if truncated and tree:
                print(
                    f"{name}: {key} HEAD tree truncated by the forge, "
                    "rename search is partial",
                    file=sys.stderr,
                )
        return context[key]

    def rename_getter(path: str, role: str = "") -> tuple[str | None, list[str]]:
        """Resolved only when a cited file has vanished, then memoised.

        Every declared repository is searched, not just the one that owns the
        path: a profile citing both a port and its upstream may point at a file
        that only the other one carries.
        """
        owner, actual = resolve_path(path, role=role)
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
        if not candidates and any(v.repo.slug in truncated_trees for v in ordered):
            return None, [TREE_TRUNCATED]
        return None, candidates

    # Pin trees before HEAD trees, each read only when reached.
    refs = _resolve_project_words(
        refs,
        lambda: itertools.chain(
            map(_pin_tree_for, views), map(lambda v: _context_for(v)[1], views)
        ),
        lambda: (
            upstream.list_gitlinks(v.repo, v.pin, cache_dir, offline) for v in views
        ),
    )

    lines_cache: dict[tuple[str, str, int | None], list[str] | None] = {}

    def fetch(
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
        key = (which, path, start, tokens, forced and forced.repo.slug, role)
        if key not in lines_cache:
            view, actual = (
                (forced, path) if forced
                else resolve_path(path, start, tokens, role)
            )
            sha = view.pin if which == PIN else view.head
            found = fetch_from(view.repo, sha, actual)
            if found is None:
                # Not cached: the miss may be a repository that has just been
                # muted, and the next call resolves the path to a mirror that
                # does carry it. upstream.fetch_file holds its own cache, so
                # asking again costs a lookup rather than a request.
                return None
            lines_cache[key] = found
        return lines_cache[key]

    def describe(
        path: str,
        start: int | None = None,
        tokens: Iterable[str] = (),
        forced: RepoView | None = None,
        role: str = "",
    ) -> tuple[str | None, str, str]:
        view, actual = (
            (forced, path) if forced
            else resolve_path(path, start, tuple(tokens), role)
        )
        slug = view.repo.slug if view is not primary else None
        return slug, upstream.raw_url(view.repo, view.head, actual), actual

    def anchor_across_views(part: RefPart, tokens: Sequence[str]) -> PartResult:
        """Judge a part against every repository that carries its path.

        A ref is only broken when it fails everywhere. `mame` cites files that
        both mamedev/mame and its libretro fork hold, with the same delimited
        token on the cited line, so no single attribution can be right for all
        of them. Taking the best outcome across repositories settles it.
        A part that names its repository is judged there alone when that
        repository carries the path: hypseus-singe cites lair.cpp under
        `source` for one entry and `upstream` for the next.
        """
        owner, _actual = resolve_path(
            part.path, part.start, tuple(tokens), role_of(part)
        )
        carrying = [
            view for view in views
            if fetch_from(view.repo, view.pin, part.path) is not None
        ]
        # Judged in the build it belongs to: the best outcome across the
        # builds of a keyed profile let the libretro tree vouch for a
        # standalone ref that had moved (xenia-edge's emulator.cc).
        meant = part.role or primary.mode
        named = [view for view in carrying if _answers(view, meant)]
        if meant and named:
            carrying = named
        live = {
            id(view) for view in carrying
            if fetch_from(view.repo, view.head, part.path) is not None
        }
        best = None
        for view in carrying:
            result = anchor_part(
                part,
                lambda which, path, start=None, toks=(), _v=view: fetch(
                    which, path, start, toks, _v
                ),
                lambda path: rename_getter(path, role_of(part)),
                lambda path, start=None, toks=(), _v=view: describe(
                    path, start, toks, _v
                ),
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
            lambda which, path, start=None, toks=(): fetch(
                which, path, start, toks, role=role_of(part)
            ),
            lambda path: rename_getter(path, role_of(part)),
            lambda path, start=None, toks=(): describe(
                path, start, toks, role=role_of(part)
            ),
            tokens,
        )

    # Comparing a revision with itself anchors every ref whatever it cites, so
    # a part whose repository already sits on HEAD is judged on
    # self-consistency instead. Decided per part, by the repository that owns
    # it: a primary on HEAD says nothing about an upstream that moved on.
    def self_checked(part: RefPart, tokens: Sequence[str]) -> bool:
        if report.pinned_tag:
            return True
        if not part.role and len(path_roles.get(part.path, ())) > 1:
            return all(on_own_revision(view) for view in views)
        view, _ = resolve_path(part.path, part.start, tuple(tokens), role_of(part))
        return on_own_revision(view)

    def judge(
        part: RefPart, flag: bool, tokens: Sequence[str], hashes: Sequence[str]
    ) -> PartResult:
        other = cites_another_version(part, profile.get("core_version"))
        if other:
            # ti99sim cites v0.0.11 beside its v0.16.0 pin: no revision of
            # the pinned repository holds that program, so it cannot anchor.
            return PartResult(
                part, "EXTERNAL", None, None, None, [],
                f"annotated for version {other}, not the documented one",
            )
        if flag:
            result = verify_at_pin(
                part,
                fetch(PIN, part.path, part.start, tokens, role=role_of(part)),
                tokens, hashes,
            )
            # Checked at its own revision, the part still lies in one tree:
            # the report names it, as a comparison does.
            owner, _actual = resolve_path(
                part.path, part.start, tuple(tokens), role_of(part)
            )
            if result.repo is None and owner is not primary:
                result = replace(result, repo=owner.repo.slug)
            if result.status == "GONE":
                # The owner is chosen on the cited first line alone. hatari's
                # port carries a longer src/paths.c than the upstream that a
                # source_ref attributes the path to, and prose citing the
                # port's 305-356 read past the end of the upstream's 345
                # lines. As in a comparison, a ref fails only everywhere.
                for view in views:
                    if view is owner or not on_own_revision(view):
                        continue
                    lines = fetch_from(view.repo, view.pin, part.path)
                    if lines is None:
                        continue
                    found = verify_at_pin(part, lines, tokens, hashes)
                    if found.status != "GONE":
                        result = replace(
                            found,
                            repo=None if view is primary else view.repo.slug,
                        )
                        break
        else:
            result = anchor_across_views(part, tokens)
        # A forge that refused the request said nothing about the file:
        # git.eden-emu.dev answers 403 to scripts, and nine citations of
        # eden-nightly read "absent at HEAD" for a file that exists.
        owner, _actual = resolve_path(
            part.path, part.start, tuple(tokens), role_of(part)
        )
        if (
            result.status in ("GONE", "AMBIGUOUS")
            and (owner.repo.host, owner.repo.slug) in mute
        ):
            return PartResult(
                part, "UNCHECKED", None, None, None, [],
                f"{owner.repo.host}/{owner.repo.slug} refused the request, not read",
            )
        return result

    staged = []
    for entry_name, ref, tokens, hashes, ref_parts, citation in refs:
        flags = [self_checked(part, tokens) for part in ref_parts]
        judged = [
            judge(part, flag, tokens, hashes)
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
    # `stella src/emucore/Cart.cxx:120` names the repository the lines are
    # in. The path was read without that word, and a recale wrote it back
    # without it: the attribution went with the old line numbers.
    word, _, rest = located.partition(" ")
    if rest.startswith(f"{part.part.path}:") and word and "/" not in word:
        span = f"{word} {span}"
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
        held = (
            f"pin held ({report.pinned_tag})" if report.pin_frozen
            else f"pinned to tag {report.pinned_tag}"
        )
        lines.append(f"  {held}: checked against its own revision, not against HEAD")
    elif report.pin and report.pin == report.head:
        lines.append("  pin is HEAD: checked for self-consistency")
    if report.upstream_tag and not report.pinned_tag:
        lines.append(
            f"  upstream pinned to tag {report.upstream_tag}: checked against "
            "its own revision, not against HEAD"
        )
    for url in report.unread or []:
        lines.append(f"  not read (unsupported host): {url}")
    for line in report.orphaned:
        lines.append(f"  orphaned pin: {line}")
    for line in report.moved_repos:
        lines.append(f"  moved repository: {line}")
    if report.declared_version or report.page_version:
        lines.append(
            f"  version page: declared {report.declared_version or '-'}, "
            f"announced {report.page_version or 'unreadable'}"
            + (" (no genuine copy found)"
               if report.page_version and report.page_version == report.no_genuine_copy
               else "")
        )
    if report.version:
        version = report.version
        lines.append(
            f"  version: declared {version.declared}, "
            f"latest tag {version.latest_tag}, "
            f"latest release {version.latest_release} ({version.release_date})"
        )
    if report.version_warning:
        lines.append(f"  {report.version_warning}")
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
    for line in report.stale_prose or ():
        lines.append(f"  prose under an older pin: {line}")
    lines.append(f"  {report.needs_review()} to review")
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
        "| profile | repository | refs | to review |",
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
    profile: dict, repo: upstream.Repo, cache_dir: str, offline: bool
) -> VersionReport | None:
    """Declared core_version against the latest upstream tag and release."""
    declared = str(profile.get("core_version") or "")
    if not declared:
        return None
    release = upstream.latest_release(repo, cache_dir, offline)
    # Asked by name: the first page of tags misses a release that a project
    # publishing nightlies has pushed past a hundred newer tags.
    commit = upstream.tag_commit(repo, declared, cache_dir, offline)
    return VersionReport(
        declared,
        upstream.newest_tag(repo, cache_dir, offline),
        release.tag if release else None,
        release.date if release else None,
        commit is not None,
        commit,
    )


def page_version(profile: dict, cache_dir: str, offline: bool) -> str | None:
    """The latest version a profile's version_source page announces.

    Forty-odd profiles live off any forge: profile_sync could only say
    "unsupported host", and a new Altirra or mednafen release went unseen.
    """
    source = profile.get("version_source") or {}
    url, pattern = str(source.get("url") or ""), str(source.get("pattern") or "")
    if not url or not pattern:
        return None
    try:
        text = upstream.fetch_page(url, cache_dir, offline)
    except upstream.UpstreamError as exc:
        print(f"{profile.get('emulator', '?')}: {url}: {exc}", file=sys.stderr)
        return None
    match = re.search(pattern, text or "")
    return match.group(1) if match else None


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


# Sources where a filename is a string. Outside a literal or a comment,
# `EE.bios` is a config key and `psm_s.pal` a struct field (pcee2).
CODE_SUFFIXES = (
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl",
    ".m", ".mm", ".rs", ".java", ".kt", ".cs", ".swift",
)
_PRINTF_SPEC_RE = re.compile(
    r"[-+ #0]*(?:\d+|\*)?(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L)?[diouxXsScpfFeEgGaA]"
)
_TITLE_WORD_RE = re.compile(r"[A-Z0-9][\w.()&'+-]*")


def _string_literal(line: str, index: int) -> tuple[int, int] | None:
    """Bounds of the double-quoted literal holding index, None outside one."""
    start = None
    position = 0
    while position < len(line):
        char = line[position]
        if char == "\\" and start is not None:
            position += 2
            continue
        if char == '"':
            if start is None:
                start = position + 1
            else:
                if start <= index < position:
                    return start, position
                start = None
        position += 1
    return None


def _in_comment(line: str, index: int) -> bool:
    before = line[:index]
    return "//" in before or "/*" in before or line.lstrip().startswith(("*", "#"))


def file_literal(line: str, start: int, end: int, code: bool) -> str | None:
    """The filename a match stands for, None when it names no file.

    A printf conversion glued to the name is not part of it: sdl2trs writes
    `"%slevel2.rom"` with ROM_PATH in front. A name with spaces is read
    whole: virtualjaguar opens `"Jaguar CD BIOS.rom"`, and the match alone
    was `BIOS.rom`. Such a name is written as a title, so `"Please insert
    bios.bin"` and `"Packing patches.zip"` still yield the file alone. In
    a code file a match outside any string or comment is an identifier and
    names nothing.
    """
    name = line[start:end]
    if start and line[start - 1] == "%":
        spec = _PRINTF_SPEC_RE.match(name)
        if spec:
            name = name[spec.end():]
    literal = _string_literal(line, start)
    if literal is None:
        if code and not _in_comment(line, start):
            return None
    elif literal[1] == end and line[start - 1:start] == " ":
        words = line[literal[0]:start].split() + [name]
        if all(_TITLE_WORD_RE.fullmatch(word) for word in words):
            return line[literal[0]:end]
    base = os.path.basename(name)
    # `".bin.hex.iii.rom"` (sdl2trs) lists extensions, it names no file.
    if base.startswith(".") or not _FILE_RE.fullmatch(base):
        return None
    return base


def detect_new_files(
    head_lines: list[str], known: set[str], cap: int = 25, path: str = ""
) -> tuple[list[tuple[int, str]], int]:
    """Filename literals at HEAD the profile does not declare."""
    found: list[tuple[int, str]] = []
    seen: set[str] = set()
    elided = 0
    code = path.lower().endswith(CODE_SUFFIXES)
    for number, line in enumerate(head_lines, start=1):
        for match in _FILE_RE.finditer(line):
            literal = file_literal(line, match.start(), match.end(), code)
            if literal is None:
                continue
            name = literal.casefold()
            if name in known or name in seen:
                continue
            seen.add(name)
            if len(found) >= cap:
                elided += 1
                continue
            found.append((number, literal))
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
PIN_WEIGHT = 50


def drift_score(
    report: ProfileReport, version: VersionReport | None, commits: int
) -> int:
    """Rank profiles by how far they have drifted from their pin."""
    counts = report.counts or {}
    score = sum(DRIFT_WEIGHTS.get(k, 0) * v for k, v in counts.items())
    # Prose a reader has to settle weighs as an ambiguous ref, prose
    # --realign-prose moves by itself as a shifted one.
    score += sum(
        DRIFT_WEIGHTS["SHIFTED" if line.startswith("would recale") else "AMBIGUOUS"]
        for line in report.stale_prose or ()
    )
    if version is not None and not version.tag_matches_declared:
        if version.latest_release and version.latest_release != version.declared:
            score += 10
    # A pin off its branch or a repository answering under another name is
    # set again before any ref can be read, so each outranks a GONE ref:
    # pcem ranked last at 0 with an orphaned upstream_commit.
    score += PIN_WEIGHT * (len(report.orphaned) + len(report.moved_repos))
    # A profile no repository answers for cannot be read at all, and
    # --strict fails on it: it ranked at 0 under the clean profiles.
    score += PIN_WEIGHT * report.uncheckable()
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
    """The value of a `key: value` line as the loader reads it.

    etlegacy quotes `(FS_FOpenFileRead \\"pak0.pk3\\")` inside a double-quoted
    source_ref: stripping the outer quotes keeps the backslashes, and the
    line never equalled the parsed value it was searched for.
    """
    raw = line.split(":", 1)[1].strip()
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError:
        parsed = None
    if isinstance(parsed, str):
        return parsed
    return raw.strip('"').strip("'")


def _double_quoted(value: str) -> str:
    """A YAML double-quoted scalar reading back as value."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


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
    lines[index] = f"{indent}{key}: {_double_quoted(value)}"
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


# Key order of a written version_basis, as a reader expects it.
_BASIS_ORDER = ("kind", "why", "repo", "url", "commit", "path", "pattern", "format",
                "match", "tag", "distance", "of", "artifact")


def _top_block(lines: list[str], key: str) -> tuple[int, int] | None:
    """Line span of a top-level key and the indented lines under it."""
    indices = _top_level_indices(lines, key)
    if not indices:
        return None
    if len(indices) > 1:
        raise YamlWriteError(f"{key}: expected one top-level line, found {len(indices)}")
    end = indices[0] + 1
    while end < len(lines) and (lines[end].startswith((" ", "\t")) or not lines[end].strip()):
        end += 1
    # Blank lines closing the block belong to the document, not to it.
    while end > indices[0] + 1 and not lines[end - 1].strip():
        end -= 1
    return indices[0], end


def _render_version(value: object) -> list[str]:
    if isinstance(value, dict):
        return ["core_version:"] + [
            f"  {mode}: {'null' if v is None else _double_quoted(str(v))}"
            for mode, v in value.items()
        ]
    return [f"core_version: {'null' if value is None else _double_quoted(str(value))}"]


def _render_basis(basis: dict) -> list[str]:
    def ordered(entry: dict) -> dict:
        rank = {key: i for i, key in enumerate(_BASIS_ORDER)}
        return dict(sorted(entry.items(), key=lambda item: rank.get(item[0], len(rank))))

    def scalar(value: object) -> str:
        # Every string quoted: a tag 2407 or 0.10 read back as a number. A
        # pattern keeps its backslashes readable in single quotes.
        if isinstance(value, bool) or not isinstance(value, str):
            return str(value).lower() if isinstance(value, bool) else str(value)
        if "\\" in value or '"' in value:
            return "'" + value.replace("'", "''") + "'"
        return _double_quoted(value)

    def block(entry: dict, indent: str) -> list[str]:
        # kind, why and repo are words of the schema's enums, written bare.
        return [f"{indent}{key}: {value if key in ('kind', 'why', 'repo') else scalar(value)}"
                for key, value in ordered(entry).items()]

    if "kind" in basis:
        return ["version_basis:", *block(basis, "  ")]
    lines = ["version_basis:"]
    for mode, entry in basis.items():
        lines += [f"  {mode}:", *block(entry, "    ")]
    return lines


def set_version_fields(text: str, version: object, basis: dict | None) -> str:
    """Rewrite core_version and version_basis, version_basis right after it."""
    lines = text.splitlines()
    span = _top_block(lines, "core_version")
    rendered = _render_version(version)
    if span is None:
        anchor = _top_block(lines, "upstream_commit") or _top_block(lines, "source_commit") \
            or _top_block(lines, "profiled_date") or _top_block(lines, "upstream") \
            or _top_block(lines, "source") or _top_block(lines, "alias_of") \
            or _top_block(lines, "type")
        if anchor is None:
            raise YamlWriteError("core_version: no line to write it after")
        lines[anchor[1]:anchor[1]] = rendered
    else:
        lines[span[0]:span[1]] = rendered
    if basis is not None:
        old = _top_block(lines, "version_basis")
        if old is not None:
            del lines[old[0]:old[1]]
        after = _top_block(lines, "core_version")
        lines[after[1]:after[1]] = _render_basis(basis)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def apply_readings(document: dict, readings: list) -> tuple[object, dict | None]:
    """core_version and version_basis as the readings state them.

    A reading that could not be made leaves its build mode as written.
    """
    version = document.get("core_version")
    basis = document.get("version_basis")
    basis = dict(basis) if isinstance(basis, dict) else None
    if isinstance(version, dict):
        version = dict(version)
    for reading in readings:
        if reading.status not in (version_basis.MATCH, version_basis.DRIFT):
            continue
        if reading.mode:
            if not isinstance(version, dict):
                version = {}
            version[reading.mode] = reading.read
        else:
            version = reading.read
        if reading.updates and basis is not None:
            target = basis if not reading.mode else dict(basis.get(reading.mode) or {})
            target.update(dict(reading.updates))
            if reading.mode:
                basis[reading.mode] = target
    return version, basis


def write_version(path: Path, readings: list) -> bool:
    """Set core_version (and a tag basis' tag and distance) from the readings."""
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    version, basis = apply_readings(document, readings)
    if version == document.get("core_version") and basis == document.get("version_basis"):
        return False
    expected = dict(document)
    expected["core_version"] = version
    if basis is not None:
        expected["version_basis"] = basis
    apply_edit(path, set_version_fields(text, version, basis), expected)
    return True


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


_RANGE_TOKEN_RE = re.compile(r"\d+(?:-\d+)?")


def _run_after_moves(
    parts: Sequence[RefPart],
    moves: dict[int, tuple[int, int, str | None]],
    run: str = "",
) -> str:
    """The prose run as it reads once its moved ranges are rewritten.

    The path is the one written in the run: a part can carry a project word
    or the tree path the report resolved it to, neither of which the
    sentence spells.
    """
    new_path = next(
        (move[2] for move in moves.values() if move[2]), None
    ) or (run.split(":", 1)[0] if run else None)
    ranges = []
    for index, part in enumerate(parts):
        if index in moves:
            start, end, _ = moves[index]
            ranges.append(f"{start}" if end == start else f"{start}-{end}")
        else:
            ranges.append(part.raw)
    # The separators stay as written. boom3 writes `libretro.cpp:1635-1643,
    # 2384-2405` in a folded scalar, rewritten whole there, and a joined
    # `3238-3246,4245-4266` no longer read as the intended document.
    written = run.partition(":")[2]
    tokens = list(_RANGE_TOKEN_RE.finditer(written))
    if len(tokens) == len(parts) and all(
        token.group() == part.raw for token, part in zip(tokens, parts)
    ):
        for token, rendered in reversed(list(zip(tokens, ranges))):
            written = written[:token.start()] + rendered + written[token.end():]
        return f"{new_path or parts[0].path}:{written}"
    return f"{new_path or parts[0].path}:{','.join(ranges)}"


def _unique_line(
    lines: list[str], target: str, window: tuple[int, int]
) -> int | None:
    """The one line of the window carrying target, None when not exactly one."""
    hits = [
        i for i in range(window[0], min(window[1], len(lines) - 1) + 1)
        if target and target in lines[i]
    ]
    return hits[0] if len(hits) == 1 else None


def scalar_windows(
    text: str, document: object
) -> dict[tuple[int, object], tuple[int, int]]:
    """Physical lines each scalar spans, keyed by its holder and key.

    The same sentence can sit in two fields: emucorex cites
    CMakeLists.txt:706 in notes and in exclusion_note, on identical lines.
    Searched over the whole file neither occurrence was unique, and only
    the node's own lines tell them apart.
    """
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return {}
    windows: dict[tuple[int, object], tuple[int, int]] = {}

    def walk(value: object, node: yaml.Node | None) -> None:
        if isinstance(value, dict) and isinstance(node, yaml.MappingNode):
            by_key = {str(k.value): v for k, v in node.value}
            for key, item in value.items():
                child = by_key.get(str(key))
                if child is None:
                    continue
                windows[(id(value), key)] = (
                    child.start_mark.line, child.end_mark.line
                )
                walk(item, child)
        elif isinstance(value, list) and isinstance(node, yaml.SequenceNode):
            for index, (item, child) in enumerate(zip(value, node.value)):
                windows[(id(value), index)] = (
                    child.start_mark.line, child.end_mark.line
                )
                walk(item, child)

    walk(document, root)
    return windows


def _apply_prose_edits(
    text: str, jobs: list[tuple[Citation, dict]], document: object = None
) -> tuple[str, list[str], list[str]]:
    """Rewrite prose citation tokens in place, nothing else.

    Each scalar line a run touches is located as the unique physical line
    carrying it. Two candidate lines, or none, means the write cannot be
    proved right, so the run is left alone and reported with the reason. A
    comment run is rewritten on its own physical line, once the tokens there
    read as collected. All replacements of one line are applied together,
    right to left, so the spans measured on the original text stay valid.
    """
    lines = text.splitlines()
    trailing = "\n" if text.endswith("\n") else ""
    file_edits: dict[int, list[tuple[int, int, str]]] = {}
    value_edits: dict[tuple[int, object], dict[int, list]] = {}
    holders: dict[tuple[int, object], tuple] = {}
    applied: list[str] = []
    left: list[str] = []
    windows = scalar_windows(text, document) if document is not None else {}
    whole = (0, len(lines) - 1)

    for citation, moves in jobs:
        replacements = []
        for index, (start, end, _) in moves.items():
            lo, hi = citation.spans[index]
            replacements.append(
                (lo, hi, f"{start}" if end == start else f"{start}-{end}")
            )
        new_path = next((m[2] for m in moves.values() if m[2]), None)
        if new_path:
            replacements.append((*citation.path_span, new_path))
        recaled = _run_after_moves(citation.parts, moves, citation.ref)

        if citation.in_comment:
            # The comment is read again from the text being written: a run
            # whose tokens no longer sit at the collected offsets is left.
            line = lines[citation.line] if citation.line < len(lines) else ""
            expected = [p.raw for p in citation.parts] + [citation.ref.split(":", 1)[0]]
            spans = list(citation.spans) + [citation.path_span]
            if any(line[lo:hi] != token for (lo, hi), token in zip(spans, expected)):
                left.append(f"{citation.field}: {citation.ref} (comment changed)")
                continue
            file_edits.setdefault(citation.line, []).extend(replacements)
            applied.append(f"{citation.field}: {citation.ref} -> {recaled}")
            continue

        value = str(citation.holder[citation.key])
        value_lines = value.splitlines()
        last = citation.line + (1 if citation.wrapped else 0)
        if last >= len(value_lines):
            left.append(f"{citation.field}: {citation.ref} (scalar changed)")
            continue
        # A wrapped run puts its spans back on the two scalar lines it
        # joined: playdiaemu wrote `content.rs` and `:111-199` one line apart.
        by_line: dict[int, list[tuple[int, int, str]]] = {}
        straddles = False
        for lo, hi, new in replacements:
            if citation.wrapped and lo >= citation.joined_at:
                following = value_lines[last]
                indent = len(following) - len(following.lstrip())
                shift = indent - citation.joined_at
                by_line.setdefault(last, []).append((lo + shift, hi + shift, new))
            elif citation.wrapped and hi > citation.joined_at:
                straddles = True
            else:
                by_line.setdefault(citation.line, []).append((lo, hi, new))
        if straddles:
            left.append(f"{citation.field}: {citation.ref} (a token spans the line break)")
            continue
        window = windows.get((id(citation.holder), citation.key), whole)
        located = {
            number: _unique_line(lines, value_lines[number], window)
            for number in by_line
        }
        if citation.wrapped and (
            None in located.values()
            or (len(located) == 2 and located[last] != located[citation.line] + 1)
        ):
            left.append(
                f"{citation.field}: {citation.ref} "
                "(wrapped, and its two lines are not found together in the file)"
            )
            continue
        if None not in located.values():
            for number, edits in by_line.items():
                hit = located[number]
                offset = lines[hit].index(value_lines[number])
                file_edits.setdefault(hit, []).extend(
                    (offset + lo, offset + hi, new) for lo, hi, new in edits
                )
        else:
            # A folded scalar has no physical line carrying its logical one.
            # The run itself is a single word, which folding never breaks:
            # when the whole file carries it exactly once, that occurrence
            # is the citation, and the run is rewritten as one token. The
            # match is delimited, or `x.c:481` would also hit inside a
            # neighbouring `x.c:481-482`.
            pattern = re.compile(
                rf"(?<![\w/.-]){re.escape(citation.ref)}(?![\w-])"
            )
            run_hits = [
                i for i in range(window[0], min(window[1], len(lines) - 1) + 1)
                if pattern.search(lines[i])
            ]
            if (
                len(run_hits) != 1
                or len(pattern.findall(lines[run_hits[0]])) != 1
            ):
                carriers = sum(
                    1 for line in lines[window[0]:window[1] + 1]
                    if value_lines[citation.line] and value_lines[citation.line] in line
                )
                left.append(
                    f"{citation.field}: {citation.ref} "
                    f"({carriers} lines carry its sentence)"
                )
                continue
            low = pattern.search(lines[run_hits[0]]).start()
            file_edits.setdefault(run_hits[0], []).append(
                (low, low + len(citation.ref), recaled)
            )
        slot = (id(citation.holder), citation.key)
        holders[slot] = (citation.holder, citation.key)
        for number, edits in by_line.items():
            value_edits.setdefault(slot, {}).setdefault(number, []).extend(edits)
        applied.append(f"{citation.field}: {citation.ref} -> {recaled}")

    for number, replacements in file_edits.items():
        lines[number] = _replace_spans(lines[number], replacements)
    for slot, edits in value_edits.items():
        holder, key = holders[slot]
        value = str(holder[key])
        value_lines = value.splitlines()
        for line_number, replacements in edits.items():
            value_lines[line_number] = _replace_spans(
                value_lines[line_number], replacements
            )
        holder[key] = "\n".join(value_lines) + (
            "\n" if value.endswith("\n") else ""
        )
    return "\n".join(lines) + trailing, applied, left


def _replace_spans(line: str, replacements: list[tuple[int, int, str]]) -> str:
    """Apply span replacements measured on the original line."""
    for lo, hi, new in sorted(replacements, reverse=True):
        line = line[:lo] + new + line[hi:]
    return line


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
            and _rendered_part(part) != _original_part(part)
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


def _view_role(view: RepoView) -> str:
    """source or upstream: the profile field a repository comes from."""
    return "upstream" if view.field == "upstream" else "source"


def _answers(view: RepoView, role: str) -> bool:
    """Whether a part written under *role* means this repository: the field
    it comes from, or the build mode a keyed source declares it under."""
    return bool(role) and role in (_view_role(view), view.mode)


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
            raw = part.part.raw or _original_part(part)
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
    if report.pinned_tag:
        return []
    statuses = REBASE_STATUSES + (("CHANGED",) if accept_changed else ())
    blocking = [s for s in REVIEW_STATUSES if s not in statuses]
    if any((report.counts or {}).get(s) for s in blocking):
        return []
    blockers = pin_blockers(report, accept_changed)
    if blockers:
        # Something here will not move: an annotated ref, one under a mode
        # key, or a prose run this pass cannot rewrite without guessing.
        # bump_commit will refuse while it stands, and recaling the rest
        # would leave the profile describing two revisions at once. All or
        # nothing means the pin too, not only the refs.
        _refuse_recale(path, blockers)
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
            if any(
                part.status in statuses
                and part.start is not None
                and _rendered_part(part) != _original_part(part)
                for part in entry.parts
            ):
                refused.append(
                    f"{entry.name}: {entry.source_ref} (under a mode key, moved by hand)"
                )
            continue
        if not _is_rewritable(entry.source_ref):
            # Rewriting would drop the author's annotations. Still consume
            # the line so a later entry carrying the same ref cannot match it.
            cursor = find_field_line(text, "source_ref", entry.source_ref, cursor) + 1
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
            cursor = find_field_line(text, "source_ref", entry.source_ref, cursor) + 1
            continue
        new_ref = ", ".join(rendered)
        text, index = replace_field_line(
            text, "source_ref", entry.source_ref, new_ref, cursor
        )
        cursor = index + 1
        citation.holder[citation.key] = new_ref
        applied.append(f"{entry.source_ref} -> {new_ref}")

    text, prose_applied, left = _apply_prose_edits(text, prose_jobs, document)
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


def _citation_key(ref: str) -> str:
    """A citation compared without the spacing the author chose.

    A recale rewrites the located tokens and leaves the sentence alone, so
    `a.c:228, 1439-1443` keeps its space while the rendered form drops it.
    They are the same citation, and comparing them literally makes a run
    that was written look unwritten, which holds the pin back for ever.
    """
    return re.sub(r"\s+", "", ref)


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
            and _rendered_part(part) != _original_part(part)
        )
    if document is None:
        return pending

    pool: dict[tuple[str, str], int] = {}
    for citation in collect_citations(document, text):
        if citation.kind == "prose":
            slot = (citation.field, _citation_key(citation.ref))
            pool[slot] = pool.get(slot, 0) + 1
    for entry in report.entries or []:
        if entry.kind != "prose":
            continue
        moves = _prose_moves(entry, movable)
        if not moves:
            # Either nothing has to move, or the run cannot be written
            # without guessing, and the second case still blocks the pin.
            if any(
                part.status in movable
                and part.start is not None
                and (
                    (part.start, part.end) != (part.part.start, part.part.end)
                    or part.new_path
                )
                for part in entry.parts
            ):
                pending += 1
            continue
        rendered = _run_after_moves(
            [p.part for p in entry.parts], moves, entry.source_ref
        )
        if _citation_key(rendered) == _citation_key(entry.source_ref):
            continue
        slot = (entry.field, _citation_key(rendered))
        if pool.get(slot, 0) > 0:
            pool[slot] -= 1
            continue
        pending += 1
    return pending


NO_SOURCE_REF = "no source_ref"


def _needs_review(report: ProfileReport, accept_changed: bool) -> bool:
    """Whether the report leaves a ref to read before the pin may move."""
    # A profile citing nothing has nothing to read again: anarch's pin sat
    # behind a CI-only commit through every bulk advance.
    if report.skipped not in (None, NO_SOURCE_REF) or not report.head or report.pinned_tag:
        return True
    blocking = REVIEW_STATUSES if not accept_changed else (
        s for s in REVIEW_STATUSES if s != "CHANGED"
    )
    return any((report.counts or {}).get(s) for s in blocking)


@functools.lru_cache(maxsize=4)
def _platform_cores(emulators_dir: str, platforms_dir: str) -> tuple[tuple[str, frozenset[str]], ...]:
    profiles = load_emulator_profiles(emulators_dir)
    return tuple(
        (platform, frozenset(resolve_platform_cores(
            load_platform_config(platform, platforms_dir), profiles
        )))
        for platform in list_registered_platforms(platforms_dir)
    )


def shipping_platforms(
    name: str, emulators_dir: str, platforms_dir: str = "platforms",
) -> list[str]:
    """The registered platforms whose cores resolve to this profile."""
    return [
        platform
        for platform, cores in _platform_cores(
            os.path.realpath(emulators_dir), platforms_dir
        )
        if name in cores
    ]


def bump_commit(
    path: Path, report: ProfileReport, accept_changed: bool = False,
    cache_dir: str = DEFAULT_CACHE, offline: bool = False,
    platforms_dir: str = "platforms",
) -> bool:
    """Advance source_commit to HEAD when nothing needs a read again.

    core_version moves with the pin, read again from version_basis at the
    new revision. Four bulk advances moved 295 pins and no version: an
    advance whose version cannot be read is refused.
    """
    if _needs_review(report, accept_changed):
        return False
    text = path.read_text(encoding="utf-8")
    if pending_recale(report, accept_changed, text):
        return False
    document = yaml.safe_load(text)
    if document.get("built_by"):
        # The pin is the commit a platform builds (recalbox gsplus.mk, the
        # mame0258 its package fetches), not a point on a moving branch:
        # HEAD is a build nobody ships under this name.
        print(
            f"{path.stem}: pinned to the build {', '.join(document['built_by'])} "
            "ships, advanced by hand",
            file=sys.stderr,
        )
        return False
    if not (document.get("pin_frozen") or document.get("pin_follows")):
        shipped = shipping_platforms(path.stem, str(path.parent), platforms_dir)
        if len(shipped) == 1:
            # One platform ships it, so the pin is the revision that platform
            # builds: a bulk advance moved fheroes2, supertux and
            # supermariowar past what EmuELEC compiles, and rigelengine is
            # already one commit ahead of its package.mk.
            print(
                f"{path.stem}: only {shipped[0]} ships it. Read the revision its "
                "build compiles and set pin_frozen, or pin_follows when it "
                "builds the branch tip",
                file=sys.stderr,
            )
            return False
    if any(isinstance(document.get(f), dict) for f in ("source_commit", "upstream_commit")):
        # A pin per build mode names one revision per repository, and the
        # report heads only the primary one: rewriting str(dict) was a
        # refused write on mesence, supermodel and xemu.
        print(
            f"{path.stem}: pins keyed by build mode are advanced by hand",
            file=sys.stderr,
        )
        return False
    # An upstream pinned on a release tag is the base the port was cut from:
    # its HEAD is another program, so the bump leaves it on the tag.
    # A profile citing nothing compared nothing upstream: writing that HEAD
    # would claim gme's vendored libgme or hbmame's port is current.
    upstream_moves = bool(
        report.upstream_head
        and report.upstream_pin != report.upstream_head
        and not report.upstream_tag
        and report.skipped != NO_SOURCE_REF
    )
    if document.get("source_commit") == report.head and not upstream_moves:
        # Rewriting the pin to the value it already holds is not a bump, and
        # announcing it buries the profiles that did move.
        return False
    if (
        document.get("source_commit") != report.head
        and not cites_primary(report)
    ):
        # Every ref anchored in another repository: HEAD of this one was
        # never compared with anything. gam4980's pin moved to the fork's
        # HEAD while its bare libretro.c refs still described upstream.
        print(
            f"{path.stem}: no ref resolves in {report.repo}, its pin is not advanced",
            file=sys.stderr,
        )
        return False
    expected = dict(document)
    expected["source_commit"] = report.head
    new_text = _set_pin(text, document, "source_commit", report.head, "profiled_date")
    if upstream_moves:
        expected["upstream_commit"] = report.upstream_head
        new_text = _set_pin(
            new_text, document, "upstream_commit", report.upstream_head, "source_commit"
        )
    readings = version_basis.check(expected, cache_dir, offline, recompute=True)
    refused = version_refusal(readings)
    if refused:
        print(f"{path.stem}: {refused}, its pin is not advanced", file=sys.stderr)
        return False
    version, basis = apply_readings(expected, readings)
    if version != expected.get("core_version") or basis != expected.get("version_basis"):
        new_text = set_version_fields(new_text, version, basis)
        expected["core_version"] = version
        if basis is not None:
            expected["version_basis"] = basis
    apply_edit(path, new_text, expected)
    return True


def version_refusal(readings: list) -> str | None:
    """Why the version at a new pin cannot be stated, or None."""
    for reading in readings:
        if reading.status == version_basis.NO_BASIS:
            return "no version_basis says where its version is read"
        if reading.status == version_basis.UNREADABLE:
            return f"core_version cannot be read at the new pin: {reading.where}"
        if reading.status == version_basis.UNCHECKED:
            return f"core_version is {reading.where}, not read from the code at a pin"
    return None


def pins_changed(before: dict, after: dict) -> list[str]:
    """The pin fields whose value a write changed."""
    return [
        pin for pin in ("source_commit", "upstream_commit")
        if after.get(pin) and after.get(pin) != before.get(pin)
    ]


def cites_primary(report: ProfileReport) -> bool:
    """Whether a ref resolved in the repository source_commit pins.

    A part attributed to another declared repository carries its slug, and one
    read in the primary carries none. A profile citing nothing proves
    nothing either way and is not held back.
    """
    if len(report.repos) < 2:
        return True
    parts = [
        part for entry in report.entries for part in entry.parts
        if part.status != "EXTERNAL"
    ]
    return not parts or any(part.repo is None for part in parts)


def _set_pin(text: str, document: dict, field: str, value: str, after: str) -> str:
    """Write *field* as *value*, replacing its line or adding one after *after*."""
    current = document.get(field)
    if current == value:
        return text
    if current:
        return replace_field_line(text, field, str(current), value)[0]
    return insert_after_line(text, after, f'{field}: "{value}"')


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
) -> tuple[str, object]:
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
) -> tuple[str, object] | None:
    """One range, anchored from its writing revision to the current pin.

    `pinned` lists every declared (repository, current pin). A path no moved
    repository carries but an unmoved one does lives where nothing moved:
    it needs no move, and calling it absent made two readings of the same
    history disagree on every run (nethersx2's AetherSX2 citations).
    """
    if is_external_citation(part.path):
        return None
    # The path as written decides first, as attribution does: a prefix is
    # stripped only when no declared repository carries the path itself.
    # hatarib's hatari/src/tos.c lives in hatariB, which did not move, and
    # stripping the prefix read it as hatari/hatari's src/tos.c instead.
    # Between two repositories that both carry the path, the one declared
    # first owns it, as in attribution: freej2me-plus and hex007/freej2me
    # both hold src/libretro/, and the citations describe the fork.
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
    unclear = None
    for repo, written, current in literal or pairs:
        state, payload = _resolve_at(repo, written, part.path, cache_dir, offline)
        if state == "unclear":
            unclear = payload
            continue
        if state == "missing":
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
        if anchored.status == "SHIFTED":
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
                _realign_part(part, pairs, cache_dir, offline, pinned) if pairs else None
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
        state, payload = outcome
        if state == "ok":
            moves[index] = (payload[0], payload[1], None)
        else:
            blocked.append(payload)
    return moves, blocked


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
    # Every repository the profile declares, by build mode where it keys
    # them so: eka2l1, mesence, supermodel and xemu pin a dict, and reading
    # str(dict) found no repository at all, so their prose was never judged.
    repos = [
        (field, mode, repo)
        for field, mode, url in declared_repositories(document)
        if field != "source_mirror" and (repo := upstream.parse_repo(url)) is not None
    ]
    if not repos:
        return []
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
    history = _git_history(path)
    if history is None:
        return [f"read again: {path.name}: git history unreadable"]
    if not history:
        return []

    # Each citation is followed on its own: a field's text changes whenever
    # one of its citations is corrected by hand, and dating the whole field
    # from that commit put idtech4a++'s untouched Game.java:69-72 under the
    # current pin, so the stale range was never offered again.
    keys = [(c.field, _citation_key(c.ref)) for c in citations]
    alive = [True] * len(citations)
    intro: list[str | None] = [None] * len(citations)
    revisions: list[tuple[str, dict]] = []
    # Citations whose writing pin lies past a revision that cannot be read:
    # where their text came in is unknown, so they are not moved.
    unknown: dict[int, str] = {}
    # A revision that does not parse is passed over unless the pins differ
    # on its two sides while the citation is absent across it: then the
    # text may have come in there under either pin. Otherwise nothing
    # it could hold changes the reading. lindbergh-loader
    # committed invalid YAML once (df7346b3), fixed the same day, and every
    # note older than that commit stayed blocked for good.
    gap: str | None = None

    def carried_by(past: dict) -> set[tuple[str, str]]:
        return {
            (c.field, _citation_key(c.ref))
            for c in collect_citations(past) if c.kind == "prose"
        }

    for sha in history:
        if not any(alive):
            break
        past = _git_file_at(path, sha)
        if past is None:
            gap = gap or sha
            continue
        held = carried_by(past)
        if gap:
            newer = revisions[-1][1] if revisions else document
            moved = any(
                newer.get(pin) != past.get(pin)
                for pin in ("source_commit", "upstream_commit")
            )
            for index, live in enumerate(alive):
                if live and moved and keys[index] not in held:
                    unknown[index] = gap
                    alive[index] = False
            gap = None
        revisions.append((sha, past))
        for index, live in enumerate(alive):
            if not live:
                continue
            if keys[index] in held:
                intro[index] = sha
            else:
                alive[index] = False
    if gap:
        # The oldest revisions do not parse: where the text came in is past
        # what can be read.
        unknown.update({index: gap for index, live in enumerate(alive) if live})

    messages: list[str] = []
    jobs: list[tuple[Citation, dict]] = []
    for index, citation in enumerate(citations):
        if index in unknown:
            messages.append(
                f"read again: {citation.field}: {citation.ref} "
                f"(revision {unknown[index][:8]} unreadable)"
            )
            continue
        intro_sha = intro[index]
        if intro_sha is None:
            # The scalar is not committed yet: written now, under this pin.
            continue
        readings, ambiguous = _writing_pairs(
            document, repos, revisions, intro_sha, served
        )
        if not any(readings):
            continue
        moves, blocked = _realign_citation(
            citation, readings, ambiguous, cache_dir, offline, pinned
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

    if dry_run:
        messages.extend(
            f"would recale {citation.field}: {citation.ref} -> "
            f"{_run_after_moves(citation.parts, moves, citation.ref)}"
            for citation, moves in jobs
        )
        return messages
    new_text, applied, left = _apply_prose_edits(text, jobs, document)
    messages.extend(applied)
    messages.extend(f"left in place: {item}" for item in left)
    if applied:
        apply_edit(path, new_text, document)
    return messages


def _refuse_dirty_tree(emulators_dir: str, names: list[str]) -> None:
    """Writes need a clean copy of each profile they touch to roll back to.

    Only the selected profiles count: a pass writing one profile after
    another used to refuse every profile after the first it wrote.
    """
    try:
        dirty = emulators_dir_is_dirty(emulators_dir, names)
    except RuntimeError as e:
        print(f"{e}. Pass --force to write anyway.", file=sys.stderr)
        raise SystemExit(1) from e
    if dirty:
        # Another session may own the change, so the refusal names the files:
        # --force writes over them.
        one = len(dirty) == 1
        print(
            f"{', '.join(dirty)} {'has' if one else 'have'} uncommitted changes: "
            f"commit {'it' if one else 'them'} or pass --force, which writes over "
            f"{'it' if one else 'them'}.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def emulators_dir_is_dirty(emulators_dir: str, names: list[str] | None = None) -> list[str]:
    """The files of the profile directory that carry uncommitted changes.

    Paths read as the status prints them, from the repository root.

    ``names`` narrows the question to those profiles. Git is asked from
    inside the directory, so a profile tree that lives in another
    repository answers for itself. A directory git cannot read is never
    reported clean: the writes have nothing to roll back to.
    """
    paths = [f"{name}.yml" for name in names] if names is not None else ["."]
    result = subprocess.run(
        ["git", "-C", emulators_dir, "status", "--porcelain", "--", *paths],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"cannot read the git status of {emulators_dir}: {result.stderr.strip()}"
        )
    return sorted(
        line[3:].split(" -> ")[-1].strip('"')
        for line in result.stdout.splitlines()
        if line.strip()
    )


def build_parser() -> argparse.ArgumentParser:
    """Command line: selection, output, detection, writes, network."""
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Confront emulator profiles with their upstream source"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    # Repeatable: a stored value kept only the last of several --emulator.
    group.add_argument("--emulator", action="append", help="a profile, repeatable")
    group.add_argument("--all", action="store_true", help="every profile")
    group.add_argument(
        "--changed", action="store_true",
        help="the profiles the branch adds or edits against --base, "
        "uncommitted ones included",
    )
    group.add_argument(
        "--added", action="store_true",
        help="the profiles the branch adds against --base, as CI checks them",
    )
    parser.add_argument(
        "--base",
        help="revision --changed and --added compare with, through its merge "
        "base with HEAD (default: the project's main line, upstream/main or "
        "origin/main when that remote names the project, fetched otherwise)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument("--system", help="keep profiles covering this system")
    parser.add_argument("--type", dest="type_", help="keep profiles of this type")
    parser.add_argument("--stale-before", help="keep profiles profiled before a date")
    parser.add_argument("--limit", type=int, help="stop after N profiles")
    parser.add_argument(
        "--changed-only", action="store_true",
        help="list only the profiles with refs to review",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when a profile has refs to review or cannot be checked as "
        "written (no repository answers, no pin), as for a new profile in CI",
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="JSON report",
    )
    parser.add_argument(
        "--markdown", action="store_true",
        help="write a markdown report to --report-dir",
    )
    parser.add_argument(
        "--report-dir",
        default="reports",
        help="directory for the markdown report (default: reports)",
    )
    parser.add_argument(
        "--fetch-plan", action="store_true",
        help="print the upstream URLs a reader has to open",
    )
    parser.add_argument(
        "--full-diff", action="store_true",
        help="print the upstream diff of every cited file since the pin",
    )
    parser.add_argument("--ref", help="restrict --full-diff to one cited path")
    parser.add_argument(
        "--context", type=int, default=3,
        help="lines of context around each diff hunk (default: %(default)s)",
    )
    parser.add_argument(
        "--check-version", action="store_true",
        help="compare core_version with the latest tag and release",
    )
    parser.add_argument(
        "--verify-version", action="store_true",
        help="read core_version again from version_basis at the pin and "
        "exit 1 when the code states another",
    )
    parser.add_argument(
        "--set-version", action="store_true",
        help="write core_version from version_basis at the pin, the nearest "
        "tag asked of git again",
    )
    parser.add_argument(
        "--detect-new-files", action="store_true",
        help="name files upstream loads that the profile does not list",
    )
    parser.add_argument(
        "--watch-hashes", action="store_true",
        help="report hash literals that changed in the cited files",
    )
    parser.add_argument(
        "--tree-diff", action="store_true",
        help="list files added, removed or renamed upstream since the pin",
    )
    parser.add_argument(
        "--triage", action="store_true",
        help="rank the profiles by how much there is to reread",
    )
    parser.add_argument(
        "--backfill-commits", action="store_true",
        help="write source_commit for profiles that only carry profiled_date",
    )
    parser.add_argument(
        "--rebase-refs",
        action="store_true",
        help="rewrite shifted refs for HEAD and move source_commit with them, "
        "all or nothing",
    )
    parser.add_argument(
        "--attribute-refs",
        action="store_true",
        help="open each cited path with source or upstream, the repository its "
        "lines are in, for profiles that declare both",
    )
    parser.add_argument(
        "--bump-commit",
        action="store_true",
        help="move source_commit to HEAD when every ref already anchors there",
    )
    parser.add_argument(
        "--realign-prose",
        action="store_true",
        help="recale prose citations from the pin their text was written at",
    )
    parser.add_argument(
        "--accept-changed",
        action="store_true",
        help="recale CHANGED refs too, after their diff has been read",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the writes and leave the profiles untouched",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="write even when emulators/ has uncommitted changes",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="read only what the cache holds, no network access",
    )
    parser.add_argument(
        "--fresh", action="store_true",
        help="ask the forges again for branch tips, tags and releases instead "
        "of the answers cached in the last six hours",
    )
    parser.add_argument(
        "--cache-dir", default=DEFAULT_CACHE,
        help="download cache directory (default: %(default)s)",
    )
    return parser


def _git_lines(args: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise SystemExit(f"ERROR: git {' '.join(args)}: {detail}")
    return [line for line in result.stdout.splitlines() if line]


def branch_profiles(emulators_dir: str, base: str, added_only: bool) -> list[str]:
    """Names of the profiles the branch adds (or edits) against ``base``.

    The diff starts at the merge base, so commits main gained since the
    branch point are not counted, and ends at the working tree, so a
    profile not yet committed is checked too. A rename reads as an addition.
    """
    if subprocess.run(["git", "rev-parse", "--verify", "--quiet", base],
                      capture_output=True, check=False).returncode:
        remote = base.split("/", 1)[0] if "/" in base else "upstream"
        raise SystemExit(f"ERROR: {base} is not in this clone: run git fetch {remote} first")
    merge_base = _git_lines(["merge-base", base, "HEAD"])[0]
    paths = _git_lines([
        "diff", "--name-only", "--no-renames",
        "--diff-filter=A" if added_only else "--diff-filter=AM",
        merge_base, "--", emulators_dir,
    ])
    paths += _git_lines([
        "ls-files", "--others", "--exclude-standard", "--full-name",
        "--", emulators_dir,
    ])
    top = Path(_git_lines(["rev-parse", "--show-toplevel"])[0])
    root = Path(emulators_dir).resolve()
    return sorted({
        full.stem
        for path in paths
        if (full := (top / path).resolve()).suffix == ".yml" and full.parent == root
    })


def project_base() -> str:
    """The project's main line, the base --changed compares with by default.

    In a fork's clone origin/main is the fork: once the branch is pushed it
    is HEAD, and --changed --strict found nothing and passed while the PR's
    CI then failed. validate_pr.py resolves the same line the same way.
    """
    from validate_pr import _git_lines as git_lines, _project_main_line

    line = _project_main_line()
    if line:
        return line
    for remote in ("upstream", "origin"):
        if git_lines("rev-parse", "--verify", "--quiet", f"{remote}/main"):
            return f"{remote}/main"
    return "HEAD"


def select_profiles(profiles: dict, args: argparse.Namespace) -> dict:
    """Profiles matching the selection flags."""
    if args.changed or args.added:
        base = args.base or project_base()
        names = branch_profiles(args.emulators_dir, base, args.added)
        selected = {name: profiles[name] for name in names if name in profiles}
        if not selected:
            verb = "adds" if args.added else "adds or edits"
            print(f"the branch {verb} no profile against {base}", file=sys.stderr)
        return selected
    if args.emulator:
        names = [args.emulator] if isinstance(args.emulator, str) else args.emulator
        unknown = [name for name in names if name not in profiles]
        if unknown:
            # Suggested from what the listing it names shows: counted over the
            # alias and test profiles too, "lists all 553" pointed at 530 lines.
            listed = sorted(
                name for name, profile in profiles.items()
                if profile.get("type") != "alias" and profile.get("role") != "test"
            )
            raise SystemExit(
                f"ERROR: unknown profile {', '.join(unknown)}. "
                + suggest_names(unknown, listed, "python scripts/verify.py --list-emulators")
            )
        return {name: profiles[name] for name in dict.fromkeys(names)}

    # --system matches as verify.py --list-systems lists and --system selects:
    # by normalized id, so `saturn` reaches the profiles declaring sega-saturn.
    wanted_system = _norm_system_id(args.system) if args.system else None
    selected = {}
    for name, profile in sorted(profiles.items()):
        if profile.get("type") == "alias" or profile.get("role") == "test":
            continue
        if wanted_system and wanted_system not in {
            _norm_system_id(str(s)) for s in profile.get("systems") or []
        }:
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
    if not selected:
        # A misspelt filter selected nothing and the run said nothing: it
        # read as "no profile of that system needs a re-read".
        filters = ", ".join(
            f"{flag} {value}" for flag, value in (
                ("--system", args.system), ("--type", args.type_),
                ("--stale-before", args.stale_before),
            ) if value
        )
        hint = ""
        if args.system:
            # Suggested from the spellings the named listing prints.
            systems = sorted(spelling for spelling, _ in system_index(profiles).values())
            hint = " " + suggest_names([args.system], systems, "python scripts/verify.py --list-systems")
        elif args.type_:
            kinds = sorted({str(p.get("type")) for p in profiles.values() if p.get("type")})
            hint = f" Types: {', '.join(kinds)}."
        raise SystemExit(f"ERROR: no profile matches {filters or 'the selection'}.{hint}")
    return selected


def _check_quota(count: int, offline: bool) -> None:
    """Refuse a run the anonymous quota cannot carry to completion."""
    if offline or github_token():
        return
    if count * 5 > ANON_QUOTA:
        print(
            f"{count} profiles need roughly {count * 5} API calls, the anonymous "
            f"quota is {ANON_QUOTA} per hour. Log in with `gh auth login`, set "
            "GITHUB_TOKEN, or use --offline.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _stale_prose_blocks(
    name: str, path: Path, args: argparse.Namespace,
    known: list[str] | None = None,
) -> bool:
    """Whether prose written under an older pin has to move first.

    Anchored from the current pin, a recale or a bump follows someone else's
    code (boom3 FileSystem.cpp:2125, written at b810234e, an unrelated
    OpenFileRead at 132dfddb). It moves first, from the pin it was written at.
    `known` is the answer the report already holds for the same text.
    """
    stale = (
        known if known is not None
        else realign_prose(path, args.cache_dir, args.offline, dry_run=True)
    )
    if stale:
        print(
            f"{name}: {len(stale)} prose citation(s) written under an older pin; "
            "run --realign-prose, or read them and set prose_written_at to the pin they match",
            file=sys.stderr,
        )
    return bool(stale)


def _read_stale_prose(
    name: str, path: Path, args: argparse.Namespace, failed: set[str]
) -> list[str]:
    """What --realign-prose would do or refuse on this profile, as a report.

    Read on every pass, not only before a write: prose that blocks the pin
    is review work whether or not this run tries to move it.
    """
    try:
        return realign_prose(path, args.cache_dir, args.offline, dry_run=True)
    except upstream.RateLimitError:
        raise
    except upstream.NotCachedError as exc:
        # Unread offline, as a report is: not clean, and not a failure.
        return [f"not read offline: {exc}"]
    except upstream.UpstreamError as exc:
        # Not read is not clean: the bump would refuse on the same error.
        print(f"{name}: prose not read, {exc}", file=sys.stderr)
        failed.add(name)
        return [f"not read: {exc}"]


def _backfill(
    args: argparse.Namespace, name: str, profile: dict, report: ProfileReport,
    path: Path,
) -> None:
    """Write the pin a profile without source_commit was written at."""
    if not report.pin or profile.get("source_commit"):
        return
    if args.dry_run:
        print(f"{name}: would write source_commit {report.pin[:7]}")
    elif backfill_commit(path, report.pin):
        print(f"{name}: source_commit {report.pin[:7]}")


def _apply_writes(
    args: argparse.Namespace, name: str, profile: dict, report: ProfileReport
) -> None:
    path = Path(args.emulators_dir) / f"{name}.yml"
    if not path.is_file():
        return
    if args.backfill_commits:
        _backfill(args, name, profile, report, path)
    if getattr(args, "attribute_refs", False):
        if report.skipped:
            return
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / path.name
            target.write_bytes(path.read_bytes())
            verb = "would attribute " if args.dry_run else ""
            for line in attribute_refs(target, report, profile):
                print(f"{name}: {verb}{line}")
            if not args.dry_run:
                path.write_bytes(target.read_bytes())
        return
    # A backfill has just written a pin: the report's reading predates it.
    known = None if args.backfill_commits else report.stale_prose
    if not (args.rebase_refs or args.bump_commit) or _stale_prose_blocks(
        name, path, args, known
    ):
        return
    if _gained_since_pin(args, name, profile, report):
        return
    with tempfile.TemporaryDirectory() as scratch:
        # Always work on a copy. A dry run reports what it left there, a real
        # run promotes it. A recale rewrites the refs for HEAD, so the pin
        # has to follow or neither moves: a profile whose refs describe one
        # revision and whose pin names another is exactly what the
        # all-or-nothing rule exists to prevent. Recaling alone used to
        # leave that state behind, and a later bump then read the recaled
        # refs at the old pin and saw them shifted again.
        target = Path(scratch) / path.name
        target.write_bytes(path.read_bytes())
        recale, bumped = ("would recale ", "would set ") if args.dry_run else ("", "")
        applied = []
        if args.rebase_refs and not report.skipped:
            applied = rebase_refs(target, report, args.accept_changed)
        moved = bump_commit(target, report, args.accept_changed,
                            args.cache_dir, args.offline)
        if args.rebase_refs and applied and not moved:
            keyed = any(isinstance(profile.get(f), dict) for f in ("source_commit", "upstream_commit"))
            reason = (
                "its pins are keyed by build mode and are set by hand"
                if keyed else "the prose or an annotated ref has to move first"
            )
            print(
                f"{name}: refs recaled but the pin will not follow, so nothing "
                f"was written: {reason}",
                file=sys.stderr,
            )
            return
        messages = [f"{name}: {recale}{line}" for line in applied]
        if moved:
            # Each pin the write changes, as written: a bump that only moved
            # upstream_commit announced the source_commit it already held.
            after = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
            before = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            messages += [
                f"{name}: {bumped}{pin} -> {str(after[pin])[:7]}"
                for pin in pins_changed(before, after)
            ]
        if not args.dry_run and (applied or moved):
            original = path.read_bytes()
            path.write_bytes(target.read_bytes())
            # The guard above read the prose under the pins the profile held.
            # A bump that moves upstream_commit can leave prose the report
            # judged in the fork under the new upstream pin (dolphin-mmjr2,
            # hatari, xenios): read it again on what was written. It reads
            # the profile's own history, so it runs on the real path, and a
            # read that fails (offline, rate limit) puts the profile back.
            try:
                left = realign_prose(path, args.cache_dir, args.offline, dry_run=True)
            except BaseException:
                path.write_bytes(original)
                raise
            if moved and left:
                path.write_bytes(original)
                print(
                    f"{name}: the bump would leave {len(left)} prose citation(s) "
                    "under an older pin, nothing was written. Read them first.",
                    file=sys.stderr,
                )
                return
            _WRITTEN.add(name)
        for message in messages:
            print(message)


def _gained_since_pin(
    args: argparse.Namespace, name: str, profile: dict, report: ProfileReport
) -> bool:
    """Whether the cited files gained a file name or a hash literal since the pin.

    Refs that still anchor say nothing of what the code added around them:
    mame2003_plus gained two Taito G-NET BIOS sets in a zn.c whose cited
    lines only shifted. A bump past that would document a file set the code
    no longer has. --accept-changed says the additions were read.
    """
    if args.accept_changed or not report.head or report.pin == report.head:
        return False
    if report.pinned_tag:
        # A held pin is not advanced at all: bump_commit says so itself.
        return False
    if report.new_files is None and report.new_hashes is None:
        probe = argparse.Namespace(**{**vars(args), "detect_new_files": True, "watch_hashes": True})
        _attach_detection(probe, profile, report)
    gained = sorted({item["name"] for item in report.new_files or () if item.get("since_pin")})
    added = report.new_hashes or []
    if not (gained or added or report.detection_skipped):
        return False
    detail = ", ".join(gained[:5]) + (f", {len(added)} hash literal(s)" if added else "")
    if report.detection_skipped:
        detail = f"cited files unread ({report.detection_skipped})"
    print(
        f"{name}: the cited files changed beyond the refs since the pin ({detail.strip(', ')}), "
        "nothing was written. Read them, then rerun with --accept-changed.",
        file=sys.stderr,
    )
    return True


def _cited_paths(report: ProfileReport) -> list[str]:
    return sorted(
        {part.new_path or part.part.path for e in report.entries for part in e.parts}
    )


def _attach_detection(
    args: argparse.Namespace, profile: dict, report: ProfileReport
) -> None:
    """Record undeclared names and hashes of the cited files on the report.

    Kept on the report rather than printed, so --json carries them as the
    text report does. A forge that refuses is named on the report: the ref
    report already muted it, and one refusal must not end a pass over every
    profile. A quota signal still ends the profile.
    """
    if not report.head or not (args.detect_new_files or args.watch_hashes):
        return
    repo = select_repo(profile)
    if repo is None:
        return
    try:
        _detect(args, profile, report, repo)
    except upstream.RateLimitError:
        raise
    except upstream.UpstreamError as exc:
        report.detection_skipped = str(exc)


def _detect(
    args: argparse.Namespace, profile: dict, report: ProfileReport,
    repo: upstream.Repo,
) -> None:
    names, hashes = declared_names(profile), declared_hashes(profile)
    new_files: list[dict] = []
    new_hashes: list[dict] = []
    for path in _cited_paths(report):
        head_lines = upstream.fetch_file(
            repo, report.head, path, args.cache_dir, args.offline
        )
        if head_lines is None:
            continue
        pin_lines = (
            upstream.fetch_file(repo, report.pin, path, args.cache_dir, args.offline)
            or []
        )
        if args.detect_new_files:
            found, elided = detect_new_files(head_lines, names, path=path)
            at_pin = {
                name.casefold()
                for _, name in detect_new_files(
                    pin_lines, names, cap=sys.maxsize, path=path
                )[0]
            }
            new_files.extend(
                {"path": path, "line": number, "name": name,
                 "since_pin": name.casefold() not in at_pin}
                for number, name in found
            )
            if elided:
                report.new_files_elided[path] = elided
        if args.watch_hashes:
            added = [
                line
                for line in difflib.unified_diff(pin_lines, head_lines, n=0)
                if line.startswith("+") and not line.startswith("+++")
            ]
            new_hashes.extend(
                {"path": path, "kind": kind, "value": value}
                for kind, value in watch_hashes(added, hashes)
            )
    if args.detect_new_files:
        report.new_files = new_files
    if args.watch_hashes:
        report.new_hashes = new_hashes


def _print_detection(report: ProfileReport) -> None:
    if report.detection_skipped:
        print(f"  extras skipped: {report.detection_skipped}")
    for item in report.new_files or ():
        print(f"  new file: {item['path']}:{item['line']}  {item['name']}")
    for path, elided in report.new_files_elided.items():
        print(f"  new file: {path}: {elided} further matches not shown")
    for item in report.new_hashes or ():
        print(f"  new {item['kind']}: {item['path']}  {item['value']}")


def _attach_version(
    args: argparse.Namespace, profile: dict, report: ProfileReport
) -> None:
    """Record core_version against the forge's latest tag and release.

    Kept on the report rather than printed, so --json carries it as the text
    report does. A forge that refuses is named on the profile's own line.
    """
    repo = select_repo(profile) if report.head else None
    if repo is None:
        return
    try:
        report.version = check_version(profile, repo, args.cache_dir, args.offline)
    except upstream.RateLimitError:
        raise
    except upstream.UpstreamError as exc:
        print(f"{report.name}: version check skipped: {exc}", file=sys.stderr)
        return
    relation = None
    passed = None
    version = report.version
    try:
        if version and version.tag_commit and report.pin and version.tag_commit != report.pin:
            relation = upstream.ancestry(
                repo, version.tag_commit, report.pin, args.cache_dir, args.offline
            )
        passed = _passed_release(args, repo, version, report.pin)
        newer = None if passed or profile.get("pin_frozen") else _newer_release(
            args, repo, version, report.pin
        )
    except upstream.RateLimitError:
        raise
    except upstream.UpstreamError as exc:
        print(f"{report.name}: tag ancestry unread: {exc}", file=sys.stderr)
        newer = None
    report.version_warning = version_warning(version, report.pin, relation, passed) or (
        f"{'release' if version.latest_release else 'tag'} {newer} is newer than core_version {version.declared} and the pin: "
        "profile it, or hold the pin with pin_frozen and the reason"
        if newer else None
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


def _newer_release(
    args: argparse.Namespace,
    repo: upstream.Repo,
    version: VersionReport | None,
    pin: str | None,
) -> str | None:
    """The latest release, when it comes after both the declared tag and the pin.

    A profile pinned on its release tag reads as clean forever: armsx1 sat on
    0.1.3, armsx2 on 2.8 and x1-box on 1.2.6 while 0.3.6, 2.9 and 1.3.2 were
    out, and nothing said so. A held pin (pin_frozen) is left alone.
    """
    published = published_version(version)
    if not version or not pin or not version.tag_commit or not published:
        return None
    if published == version.declared:
        return None
    commit = upstream.tag_commit(repo, published, args.cache_dir, args.offline)
    if not commit or commit == pin:
        return None
    after_tag = upstream.ancestry(repo, version.tag_commit, commit, args.cache_dir, args.offline)
    if not after_tag or after_tag[0] == 0 or after_tag[1] != 0:
        return None
    after_pin = upstream.ancestry(repo, pin, commit, args.cache_dir, args.offline)
    if not after_pin or after_pin[0] == 0:
        return None
    return published


def _passed_release(
    args: argparse.Namespace,
    repo: upstream.Repo,
    version: VersionReport | None,
    pin: str | None,
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
    if published == version.declared:
        return None
    if not version.tag_commit and not _later_number(published, version.declared):
        # No tag to order them: only a release numbered past the declared
        # version says it is older. "latest", "continuous" or 1.53 under a
        # declared 1.61 say nothing.
        return None
    commit = upstream.tag_commit(repo, published, args.cache_dir, args.offline)
    if not commit:
        return None
    if version.tag_commit and version.tag_commit != commit:
        # A project can publish a release older than its newest tag:
        # pcsx2x6's latest release is v0.2.20, its declared tag v0.2.22.
        older = upstream.ancestry(repo, commit, version.tag_commit, args.cache_dir, args.offline)
        if older and older[1] == 0:
            return None
    if commit == pin:
        return published
    relation = upstream.ancestry(repo, commit, pin, args.cache_dir, args.offline)
    if relation and relation[1] == 0:
        return published
    return None


def _print_extras(
    args: argparse.Namespace, profile: dict, report: ProfileReport
) -> None:
    """Optional per-profile sections beyond the ref report.

    The ref report mutes a forge that refuses, but the extras read the same
    forge again, so a refusal here is reported on the profile's own line
    instead of ending a pass over every profile. A quota signal still
    ends the profile.
    """
    _print_detection(report)
    if not (args.full_diff or args.tree_diff) or not report.head:
        return
    repo = select_repo(profile)
    if repo is None:
        return
    try:
        _print_extras_from(args, profile, report, repo)
    except upstream.RateLimitError:
        raise
    except upstream.UpstreamError as exc:
        print(f"  extras skipped: {exc}")


def _print_extras_from(
    args: argparse.Namespace, profile: dict, report: ProfileReport,
    repo: upstream.Repo,
) -> None:
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


class _Progress:
    """A stderr line every PROGRESS_SECONDS while a pass asks the forges."""

    def __init__(self, total: int, doing: str, quiet: bool) -> None:
        self.total, self.doing, self.quiet = total, doing, quiet
        self.last = time.monotonic()

    def step(self, done: int, name: str) -> None:
        now = time.monotonic()
        if not self.quiet and now - self.last >= PROGRESS_SECONDS:
            print(f"{self.doing}: {done} of {self.total}, at {name}", file=sys.stderr, flush=True)
            self.last = now


def _interrupted(done: int, total: int, what: str) -> None:
    print(f"interrupted after {done} of {total} profiles: {what}", file=sys.stderr, flush=True)


def _print_triage(
    args: argparse.Namespace, selected: dict, reports: list[ProfileReport]
) -> bool:
    """Profiles ranked by drift, worst first. False when Ctrl-C cut the
    scoring short: the ranking then covers the profiles scored."""
    ranked: list[tuple[int, ProfileReport, str]] = []
    sampled = 0
    progress = _Progress(len(reports), "scored", args.offline or len(reports) < 2)
    complete = True
    try:
        for done, report in enumerate(reports):
            progress.step(done, report.name)
            sampled += _score(args, selected, report, ranked)
    except KeyboardInterrupt:
        _interrupted(len(ranked), len(reports), "the ranking covers those scored")
        complete = False
    if sampled:
        # One line for the run: a notice per profile buried the ranking
        # under 254 lines of stderr.
        print(
            f"commit count sampled on {TRIAGE_PATH_SAMPLE} cited paths for "
            f"{sampled} profiles citing more",
            file=sys.stderr,
        )
    print(f"{'score':>5s}  {'profile':30s}  state (worst first)")
    pending = 0
    for score, report, refused in sorted(ranked, key=lambda item: -item[0]):
        state = triage_state(report)
        if refused:
            state += f", {refused}"
        pending += bool(report.needs_review() or report.uncheckable())
        print(f"{score:5d}  {report.name:30s}  {state}")
    print(f"{len(ranked)} profiles, {pending} with something to review")
    return complete


def _score(
    args: argparse.Namespace, selected: dict, report: ProfileReport, ranked: list
) -> bool:
    """Append one profile's drift score to ``ranked``. True when its commit
    count was read on a sample of the paths it cites."""
    profile = selected[report.name]
    version = None
    commits = 0
    refused = ""
    sampled = False
    repo = select_repo(profile)
    if report.head and repo is not None:
        paths = _cited_paths(report)
        try:
            version = check_version(profile, repo, args.cache_dir, args.offline)
            for path in paths[:TRIAGE_PATH_SAMPLE]:
                commits += upstream.commits_touching(
                    repo, path, report.pin, args.cache_dir, args.offline,
                    head=report.head,
                )
        except upstream.UpstreamError as exc:
            # One forge refusing a request (Eden's answers 403 to commit
            # lookups) leaves this profile unscored, not the whole ranking.
            refused = "commit history unreachable"
            print(f"{report.name}: {exc}", file=sys.stderr)
        sampled = len(paths) > TRIAGE_PATH_SAMPLE and not refused
    ranked.append((drift_score(report, version, commits), report, refused))
    return sampled


def _refuse_flag_combinations(args: argparse.Namespace) -> None:
    """Exit on a flag the chosen mode would not apply, before any request."""
    if args.verify_version or args.set_version:
        ignored = [
            flag for flag, on in (
                ("--verify-version", args.verify_version and args.set_version),
                ("--markdown", args.markdown),
                ("--fetch-plan", args.fetch_plan),
                ("--triage", args.triage),
                ("--strict", args.strict),
                ("--check-version", args.check_version),
                ("--detect-new-files", args.detect_new_files),
                ("--watch-hashes", args.watch_hashes),
                ("--full-diff", args.full_diff),
                ("--tree-diff", args.tree_diff),
                ("--backfill-commits", args.backfill_commits),
                ("--rebase-refs", args.rebase_refs),
                ("--attribute-refs", args.attribute_refs),
                ("--bump-commit", args.bump_commit),
                ("--realign-prose", args.realign_prose),
                ("--accept-changed", args.accept_changed),
                ("--dry-run", args.dry_run and not args.set_version),
            ) if on
        ]
        if ignored:
            mode = "--set-version" if args.set_version else "--verify-version"
            print(f"{mode} does not apply {', '.join(ignored)}", file=sys.stderr)
            raise SystemExit(1)
    if args.fresh and args.offline:
        print("--fresh asks the forges again, which --offline forbids.", file=sys.stderr)
        raise SystemExit(1)
    if args.accept_changed and not args.emulator:
        print(
            "--accept-changed applies to one profile at a time: its diff has "
            "to be read before its CHANGED refs can be recaled.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.attribute_refs and (
        args.rebase_refs or args.bump_commit or args.backfill_commits
        or args.realign_prose
    ):
        print(
            "--attribute-refs runs alone: it rewrites the refs the report was "
            "built from.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.realign_prose and (
        args.rebase_refs or args.bump_commit or args.backfill_commits
    ):
        print(
            "--realign-prose runs alone: the report has to be rebuilt on the "
            "realigned text before any other write.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.realign_prose:
        ignored = [
            flag for flag, on in (
                ("--json", args.as_json),
                ("--markdown", args.markdown),
                ("--fetch-plan", args.fetch_plan),
                ("--triage", args.triage),
                ("--changed-only", args.changed_only),
                ("--strict", args.strict),
                ("--check-version", args.check_version),
                ("--detect-new-files", args.detect_new_files),
                ("--watch-hashes", args.watch_hashes),
                ("--full-diff", args.full_diff),
                ("--tree-diff", args.tree_diff),
                ("--accept-changed", args.accept_changed),
            ) if on
        ]
        if ignored:
            # A mode applies a flag or refuses it, never swallows it.
            print(
                f"--realign-prose does not apply {', '.join(ignored)}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    machine = [
        flag for flag, on in (
            ("--json", args.as_json),
            ("--markdown", args.markdown),
            ("--fetch-plan", args.fetch_plan),
            ("--triage", args.triage),
        ) if on
    ]
    # The version check lives on the report, so the outputs built from the
    # report (text, --json, --markdown) carry it. A URL list and a ranking
    # do not. Detection lives on the report too, and --json carries it for
    # check_freshness. The markdown table has no column for it.
    lists_only = args.fetch_plan or args.triage
    off_json = lists_only or args.markdown
    extras = [
        flag for flag, on in (
            ("--check-version", args.check_version and lists_only),
            ("--detect-new-files", args.detect_new_files and off_json),
            ("--watch-hashes", args.watch_hashes and off_json),
            ("--full-diff", args.full_diff),
            ("--tree-diff", args.tree_diff),
        ) if on
    ]
    if machine and extras:
        # The extra sections only exist in the text report. The other outputs
        # returned before reaching them and printed as if never asked.
        print(
            f"{', '.join(machine)} does not carry {', '.join(extras)}",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _version_selection(args: argparse.Namespace, profiles: dict) -> dict:
    """--all reaches the alias and test profiles too: each states a version."""
    if args.all and not (args.system or args.type_ or args.stale_before or args.limit):
        return dict(sorted(profiles.items()))
    return select_profiles(profiles, args)


def format_reading(name: str, reading: version_basis.Reading) -> str:
    mode = f"[{reading.mode}] " if reading.mode else ""
    kind = f"{reading.kind} " if reading.kind else ""
    if reading.status == version_basis.DRIFT:
        said = f"declared {reading.declared}, code {reading.read}"
    elif reading.status == version_basis.MATCH:
        said = str(reading.read)
    else:
        said = f"declared {reading.declared}"
    return f"{name}: {mode}{reading.status} {said} ({kind}{reading.where})"


def run_versions(args: argparse.Namespace, profiles: dict) -> None:
    """--verify-version and --set-version: core_version against the code."""
    selected = _version_selection(args, profiles)
    if args.set_version and not args.dry_run and not args.force:
        _refuse_dirty_tree(args.emulators_dir, list(selected))
    counts: Counter = Counter()
    rows = []
    failed = False
    for name, profile in selected.items():
        readings = version_basis.check(
            profile, args.cache_dir, args.offline, profiles, recompute=args.set_version
        )
        for reading in readings:
            counts[reading.status] += 1
            rows.append({"profile": name, **asdict(reading)})
            if not args.as_json and (not args.changed_only or reading.status != version_basis.MATCH):
                print(format_reading(name, reading))
        if args.set_version:
            path = Path(args.emulators_dir) / f"{name}.yml"
            if args.dry_run:
                continue
            try:
                if write_version(path, readings):
                    print(f"{name}: core_version written")
            except YamlWriteError as exc:
                print(f"{name}: write refused: {exc}", file=sys.stderr)
                failed = True
        elif any(r.status in version_basis.FAILING for r in readings):
            failed = True
    if args.as_json:
        print(json.dumps(rows, indent=2))
    else:
        print(", ".join(f"{count} {status}" for status, count in sorted(counts.items())),
              file=sys.stderr)
    if failed:
        raise SystemExit(1)


def main() -> None:
    """Build one report per selected profile, then apply writes and output."""
    args = build_parser().parse_args()
    _refuse_flag_combinations(args)
    if args.fresh:
        # Tips cached before an upstream commit hid it for six hours: EKA2L1,
        # trzy/Supermodel and VICE read as behind their real HEAD.
        upstream.MOVING_TTL = 0
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    if args.verify_version or args.set_version:
        run_versions(args, profiles)
        return
    selected = select_profiles(profiles, args)
    _check_quota(len(selected), args.offline)

    writes = (
        args.backfill_commits or args.rebase_refs or args.bump_commit
        or args.realign_prose or args.attribute_refs
    )
    if writes and not args.dry_run and not args.force:
        _refuse_dirty_tree(args.emulators_dir, list(selected))

    # A profile that could not be compared or written is not a profile with
    # nothing to review: it stays in every output and fails the run.
    failed: set[str] = set()
    if args.realign_prose:
        for name in selected:
            profile_path = Path(args.emulators_dir) / f"{name}.yml"
            if not profile_path.is_file():
                continue
            try:
                before = profile_path.read_bytes()
                for line in realign_prose(
                    profile_path, args.cache_dir, args.offline, args.dry_run
                ):
                    print(f"{name}: {line}")
                if profile_path.read_bytes() != before:
                    _WRITTEN.add(name)
            except upstream.UpstreamError as exc:
                print(f"{name}: {exc}", file=sys.stderr)
                failed.add(name)
            except YamlWriteError as exc:
                print(f"{name}: write refused: {exc}", file=sys.stderr)
                failed.add(name)
        _refresh_source_paths(args)
        if failed:
            raise SystemExit(1)
        return

    reports: list[ProfileReport] = []
    quiet = args.offline or len(selected) < 2
    if not quiet:
        print(
            f"reading {len(selected)} profiles against their forges, a line every "
            f"{PROGRESS_SECONDS} s. --offline answers from the cache alone.",
            file=sys.stderr, flush=True,
        )
    progress = _Progress(len(selected), "read", quiet)
    complete = True
    try:
        for name, profile in selected.items():
            progress.step(len(reports), name)
            _read_one(args, name, profile, reports, failed, writes)
    except KeyboardInterrupt:
        # What was read is still worth printing: a ranking of 200 profiles
        # beats none after 15 minutes.
        _interrupted(len(reports), len(selected), "the output covers those read")
        complete = False

    # --changed-only narrows every output, not the text report alone: the
    # documented `--all --changed-only --json` listed every profile.
    shown = [
        report for report in reports
        if not args.changed_only or report.needs_review() or report.name in failed
    ]
    complete = _emit(args, selected, reports, shown) is not False and complete
    _refresh_source_paths(args)
    if not complete:
        raise SystemExit(130)
    if failed or (args.strict and any(
        report.needs_review() or report.uncheckable() for report in reports
    )):
        raise SystemExit(1)


def _read_one(
    args: argparse.Namespace,
    name: str,
    profile: dict,
    reports: list[ProfileReport],
    failed: set[str],
    writes: bool,
) -> None:
    """Build one profile's report into ``reports``, then apply the writes."""
    profile_path = Path(args.emulators_dir) / f"{name}.yml"
    try:
        report = _build_full_report(args, name, profile, profile_path, failed)
    except upstream.RateLimitError as exc:
        # A quota is one forge's: git.libretro.com answering 429 said
        # nothing about the 600 profiles on GitHub. upstream stops asking
        # that host, so the rest of the pass costs it nothing.
        print(f"{name}: {exc}", file=sys.stderr)
        reports.append(ProfileReport(
            name=name, entries=[], counts={},
            skipped=f"rate limited: {exc.host or exc}",
        ))
        failed.add(name)
        return
    reports.append(report)
    if writes:
        try:
            _apply_writes(args, name, profile, report)
        except YamlWriteError as exc:
            # The guard already left the file untouched, so keep going.
            print(f"{name}: write refused: {exc}", file=sys.stderr)
            failed.add(name)


# Profiles this run wrote. Their new pins name trees the site's record of
# cited source paths does not hold yet.
_WRITTEN: set[str] = set()


def _refresh_source_paths(args: argparse.Namespace) -> None:
    """Rebuild the site's record of cited source paths after a write.

    Each bump left website/src/data/source-paths.json behind its pins, and
    the site's freshness test stayed red until someone ran sitesources.py
    --fetch by hand. A run that writes nothing, or makes no request, leaves
    it alone.
    """
    if not _WRITTEN or args.dry_run or args.offline or os.environ.get("RETROBIOS_OFFLINE"):
        return
    import common  # noqa: PLC0415
    import sitesources  # noqa: PLC0415
    from common import write_if_changed  # noqa: PLC0415

    # The run loaded the profiles before writing them, and the loader caches
    # by directory: read again, the record described the pins just replaced
    # (linapple, then ten profiles in one advance).
    common._emulator_profiles_cache.clear()
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    held, unread = sitesources.build_source_paths(
        profiles, [sitesources.TREE_CACHE], fetch=True
    )
    held = sitesources.keep_unread(
        held, unread, sitesources.read_record(sitesources.SOURCE_PATHS)
    )
    sitesources.SOURCE_PATHS.parent.mkdir(parents=True, exist_ok=True)
    write_if_changed(
        str(sitesources.SOURCE_PATHS), json.dumps(held, indent=1, sort_keys=True) + "\n"
    )
    print(
        f"source paths: {sum(map(len, held.values()))} in {len(held)} trees, "
        f"{len(unread)} trees not cached: {sitesources.SOURCE_PATHS}",
        file=sys.stderr,
    )


def _build_full_report(
    args: argparse.Namespace,
    name: str,
    profile: dict,
    profile_path: Path,
    failed: set[str],
) -> ProfileReport:
    """The report of one profile, with every section the flags ask for.

    A rate limit propagates: the caller decides what one forge's quota
    means for the pass. Any other forge failure becomes a skip.
    """
    try:
        report = build_report(
            name, profile, args.cache_dir, args.offline,
            profile_path.read_text(encoding="utf-8")
            if profile_path.is_file() else None,
        )
    except upstream.RateLimitError:
        raise
    except upstream.NotCachedError as exc:
        # Offline with a cache that never stored this file: the profile
        # is unverified, not wrong. Reporting GONE sent readers after
        # files that exist.
        report = ProfileReport(
            name=name, entries=[], counts={}, skipped=f"offline: {exc}"
        )
    except upstream.GoneError as exc:
        # The forge is not coming back: a takedown, or a host that no
        # longer resolves. Saying so once in the summary beats repeating
        # it on stderr every pass, and it keeps the profile out of the
        # backlog, where nobody can act on it anyway.
        report = ProfileReport(
            name=name, entries=[], counts={}, skipped=f"upstream gone: {exc}"
        )
    except upstream.UpstreamError as exc:
        # One unreachable forge must not abandon the other profiles.
        print(f"{name}: {exc}", file=sys.stderr)
        report = ProfileReport(
            name=name, entries=[], counts={}, skipped=f"upstream error: {exc}"
        )
        failed.add(name)
    if not report.skipped and profile_path.is_file():
        report.stale_prose = _read_stale_prose(name, profile_path, args, failed)
    if args.check_version and profile.get("version_source"):
        report.declared_version = str(profile.get("core_version") or "") or None
        report.page_version = page_version(profile, args.cache_dir, args.offline)
        report.no_genuine_copy = str(
            profile["version_source"].get("no_genuine_copy") or "") or None
    if args.check_version:
        _attach_version(args, profile, report)
    _attach_detection(args, profile, report)
    return report


def _emit(
    args: argparse.Namespace,
    selected: dict,
    reports: list[ProfileReport],
    shown: list[ProfileReport],
) -> bool | None:
    """Write the reports in the form the flags ask for. False when the
    triage was cut short."""
    if args.as_json:
        print(json.dumps([report_to_dict(r) for r in shown], indent=2))
        return None
    if args.markdown:
        target = Path(args.report_dir) / f"profile-sync-{date.today().isoformat()}.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(format_markdown(shown), encoding="utf-8")
        print(f"written: {target}")
        return None
    if args.fetch_plan:
        for report in shown:
            for url in fetch_plan(report):
                print(url)
        return None
    if args.triage:
        return _print_triage(args, selected, shown)
    for report in shown:
        print(format_report(report, args.changed_only))
        _print_extras(args, selected[report.name], report)
        print()
    if args.changed_only:
        _print_elided(reports, len(shown), frozenset(report.name for report in shown))
    return None


def _print_elided(
    reports: list[ProfileReport], printed: int, listed: frozenset[str] = frozenset()
) -> None:
    """Account for what --changed-only left out, grouped by reason."""
    reasons: dict[str, int] = {}
    for report in reports:
        if report.needs_review() or report.name in listed:
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
    from common import run_cli

    run_cli(main)
