#!/usr/bin/env python3
"""Confront emulator profiles with their upstream source.

Anchors every source_ref of a profile against the commit the profile was
written at and against upstream HEAD, separating what is mechanically
recalable from what needs the code read again.
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
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
    "ANCHORED", "EXTERNAL", "BINARY", "SHIFTED", "RENAMED", "MOVED", "AMBIGUOUS",
    "CHANGED", "GONE",
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
# seconds; the ceiling sits above it so that one resolves, and still stops a
# pathological pair from stalling a sweep of every profile.
MAX_MATCH_LINES = 60000

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
            val = source.get(field)
            vals = val if isinstance(val, list) else [val] if val else []
            for v in vals:
                v = str(v).lower().removeprefix("0x")
                if v and v not in tokens:
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


_BINARY_SUFFIXES = (
    ".dll", ".exe", ".so", ".dylib", ".apk", ".elf", ".o", ".a", ".jar", ".dex",
)
_HEX_ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]{2,}")
_VERSION_WORD_RE = re.compile(r"v?\d+(\.\d+)+[\w.-]*")


def is_binary_citation(path: str) -> bool:
    """True when a ref locates code inside a shipped binary, not a source file.

    `BAM.dll 1.5-408 .text:0x100c3960-0x100c3a97`, `libmain.so LoadNES
    0x3bb49` and `.rdata dialog filter` were read by disassembly. No revision
    of any repository holds those bytes, so the ref can neither anchor nor
    break: 77 parts of `future-pinball-fploader` alone were reported GONE.
    """
    if _HEX_ADDRESS_RE.search(path):
        return True
    if " " not in path:
        # A bare `DesktopKinect.dll` names a shipped library, never a source
        # file: no directory, no line, only its import table to read.
        return "/" not in path and path.lower().endswith(_BINARY_SUFFIXES)
    head = path.split(" ", 1)[0]
    if head.lower().endswith(_BINARY_SUFFIXES):
        return True
    return head.startswith(".") and "/" not in head


def strip_repo_word(path: str, known=frozenset()) -> str:
    """Drop a leading project word that names a declared repository.

    `BAM_FPloader FPLoader.cpp:45` follows the `munt ROMInfo.cpp` convention,
    but BAM_FPloader is the profile's own source: the path is FPLoader.cpp,
    to be found in that tree, not an out-of-reach citation.
    """
    if " " not in path:
        return path
    head, _, tail = path.partition(" ")
    if head.lower() in known and tail and "/" not in head and "." not in head:
        tail = tail.strip()
        # `ArcadeFlashWeb v1.0.2 flash/flash.html` names the release the file
        # was read from; the version is not part of the path either.
        version, _, rest = tail.partition(" ")
        if rest and _VERSION_WORD_RE.fullmatch(version):
            return rest.strip()
        return tail
    return path


def narrow_by_cited(matches: list[str], cited_dirs) -> list[str]:
    """Keep the candidates under the deepest directory the profile cites.

    A bare `version.h` matches BasiliskII/src/include/version.h and
    SheepShaver/src/include/version.h in cebix/macemu; the profile's own
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
    where the CRC32s are; MAME refs point at the machine declaration, which
    carries the set name and no hash at all.
    """
    tokens = collect_tokens(entry)
    name = os.path.basename(str(entry.get("name", ""))).lower()
    stem = name.rsplit(".", 1)[0]
    if stem and stem not in tokens and len(stem) > 2:
        tokens.append(stem)
    return tokens


PROSE_CITE_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_][\w./+-]*\.[A-Za-z]\w*):(?P<range>\d+(?:-\d+)?)"
)
PROSE_CONT_RE = re.compile(r",(?P<range>\d+(?:-\d+)?)(?![\w-])(?!\.\d)")
# A spaced continuation is accepted only for a range: `x.c:55-71, 80-147`
# follows the source_ref convention, while `x.c:100, 200 files` is prose.
PROSE_CONT_SPACED_RE = re.compile(r", +(?P<range>\d+-\d+)(?![\w-])(?!\.\d)")
# Words that read as prose before a filename. Anything else in project
# position marks the citation external, the way `munt ROMInfo.cpp` does in
# a source_ref: the profile does not declare that repository.
PROSE_LINKING_WORDS = frozenset((
    "a", "an", "and", "are", "as", "at", "before", "both", "but", "by",
    "each", "for", "from", "in", "into", "is", "it", "its", "no", "not",
    "of", "on", "only", "or", "over", "per", "see", "so", "than", "that",
    "the", "their", "then", "these", "this", "those", "to", "under",
    "upstream", "uses", "via", "was", "when", "where", "while", "with",
))
_PROJECT_WORD_RE = re.compile(r"[A-Za-z0-9][\w-]*")


@dataclass(frozen=True)
class Citation:
    """One citation carried by a profile, wherever it is written.

    A structured citation lives under a source_ref key and keeps its entry
    for the values it declares. A prose citation is a path:line run found
    inside any other string scalar; its spans locate the path and every
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


def _walk_document(node, where: str = ""):
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
        for index, item in enumerate(node):
            segment = item.get("name") if isinstance(item, dict) else None
            spot = f"{where}[{segment if segment is not None else index}]"
            if isinstance(item, str):
                yield "str", spot, node, index, item
            else:
                yield from _walk_document(item, spot)


def _prose_external(line: str, path_start: int, known=frozenset()) -> bool:
    """True when the word before the path names an undeclared project.

    `munt ROMInfo.cpp:206-213` in prose follows the source_ref convention:
    the leading word is the project, and no declared repository can confirm
    the reference. The word counts as a project only when a list delimiter
    or the line start precedes it, it reads as an identifier, it is not a
    linking word, and it does not name a declared repository: in
    `boot, in libretro.cpp:12` the candidate is prose, and in
    `mednafen src/lynx/rom.cpp:55` it is the declared upstream itself.
    """
    before = line[:path_start].rstrip()
    if not before or before[-1] in ",:(":
        return False
    word_start = max(before.rfind(" "), before.rfind("\t"), before.rfind("(")) + 1
    word = before[word_start:]
    if not _PROJECT_WORD_RE.fullmatch(word):
        return False
    if word.lower() in PROSE_LINKING_WORDS or word.lower() in known:
        return False
    lead = before[:word_start].rstrip()
    return not lead or lead[-1] in ",:("


def _prose_runs(text: str, known=frozenset()):
    """Citation runs inside one prose scalar.

    A run is a path:range with its attached continuation ranges, written
    without a space after the comma the way the corpus writes them:
    `main.c:112,1624-1633` cites two ranges of one file, while `x.c:100, 200`
    is a citation followed by prose. A token carrying :// is a URL, whose
    host:port shape would otherwise pass for a citation.
    """
    for number, line in enumerate(text.splitlines()):
        consumed = 0
        for match in PROSE_CITE_RE.finditer(line):
            if match.start() < consumed:
                continue
            token_start = max(line.rfind(" ", 0, match.start()),
                              line.rfind("\t", 0, match.start())) + 1
            token = line[token_start:].split()[0] if line[token_start:] else ""
            if "://" in token:
                continue
            path = match.group("path")
            path_start = match.start("path")
            # A dotfile citation opens its token with the dot: `.gitlab-ci.yml`
            # after a delimiter is the filename, while the dot of `boot.cfg`
            # inside a word belongs to the word before it.
            if (
                path_start > 0
                and line[path_start - 1] == "."
                and (path_start == 1 or line[path_start - 2] in " \t(")
            ):
                path_start -= 1
                path = "." + path
            if _prose_external(line, path_start, known):
                consumed = match.end()
                continue
            path_span = (path_start, match.end("path"))
            spans = [(match.start("range"), match.end("range"))]
            end = match.end()
            while True:
                cont = PROSE_CONT_RE.match(line, end)
                if cont is None:
                    cont = PROSE_CONT_SPACED_RE.match(line, end)
                if cont is None:
                    break
                spans.append((cont.start("range"), cont.end("range")))
                end = cont.end()
            consumed = end
            parts = []
            for lo, hi in spans:
                rng = line[lo:hi]
                a, _, b = rng.partition("-")
                parts.append(RefPart(path, int(a), int(b or a), rng))
            yield (
                number, path_span, tuple(spans), tuple(parts),
                line[path_start:end],
            )


def collect_citations(document: dict) -> list[Citation]:
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
            continue
        for line, path_span, spans, parts, run in _prose_runs(value, known):
            citations.append(Citation(
                field=field, kind="prose", ref=run, holder=holder, key=key,
                line=line, path_span=path_span, spans=spans, parts=parts,
            ))
    return citations


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


def _written_against_head(part, head_lines) -> bool:
    """Whether the cited line exists at HEAD, which is where it was written."""
    return (
        head_lines is not None
        and part.start is not None
        and part.start <= len(head_lines)
    )


def anchor_part(
    part: RefPart, fetch, rename_getter, describe=None, tokens=()
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
        # A ref may cite a bare filename the tree search resolved at HEAD; the
        # same resolved path usually holds at the pin. A genuine rename keeps
        # the old path at the pin, which is why that one is tried first.
        pin_lines = fetch(PIN, path, part.start, tokens)
    if pin_lines is None:
        # Present at HEAD, absent at the pin, and the cited range fits the
        # HEAD file: the ref was written against HEAD while source_commit
        # still names an older revision. Saying "missing" sends the reader
        # hunting for a move that never happened; the fix is the pin.
        reason = "pin revision missing"
        if _written_against_head(part, head_lines):
            reason = "written against HEAD, pin names an older revision"
        return PartResult(part, "GONE", None, None, None, [], reason, slug, url)

    if part.start > len(pin_lines) and _written_against_head(part, head_lines):
        # The file is there and the line is not yet: the pinned revision is
        # shorter than the one the ref was written against. nestopia cited
        # the palette and database loads at 2041 and 2063, which is where
        # HEAD carries them, over a pin four hundred lines shorter.
        return PartResult(
            part, "GONE", None, None, None, [],
            "written against HEAD, pin names an older revision", slug, url,
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
    kind: str = "ref"
    field: str = ""


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
    profile: dict, repo, cache_dir: str, offline: bool, field: str = "source",
    mode: str = "", branch: str | None = None,
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
    # A port living on a branch of a fork is absent from the default tip, so
    # the branch it was read from is followed when the profile names one.
    declared = str(profile.get("source_branch") or "") or None
    for field, mode, url in declared_repositories(profile):
        repo = upstream.parse_repo(url)
        if repo is None or (repo.host, repo.slug) in seen:
            continue
        branch = branch_in_url(url) or (declared if field == "source" else None)
        pin, origin = resolve_pin(
            profile, repo, cache_dir, offline, field, mode, branch
        )
        if not pin:
            continue
        head = upstream.resolve_head(repo, cache_dir, offline, branch)
        if not head:
            continue
        seen.add((repo.host, repo.slug))
        views.append(RepoView(repo, pin, head, origin, field))
    return views


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
    the repository and the branch the port lives on.
    """
    _, sep, tail = url.partition("/tree/")
    return tail.strip("/") or None if sep else None


SELF_CHECK_CONTEXT = 2


def verify_at_pin(part: RefPart, pin_lines, tokens, hash_tokens=()) -> PartResult:
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
    if part.start > len(pin_lines):
        return PartResult(
            part, "GONE", None, None, None, [], "beyond the end of the file"
        )
    if not tokens:
        return PartResult(part, "ANCHORED", None, None, None, [])
    # An archive ref cites the line declaring the set; its members follow, one
    # per line, so the window reaches forward as far as the entry has members.
    reach = SELF_CHECK_CONTEXT + len(tokens)
    lo = max(0, part.start - 1 - SELF_CHECK_CONTEXT)
    hi = min(len(pin_lines), (part.end or part.start) + reach)
    window = "\n".join(pin_lines[lo:hi]).lower()
    if any(token in window for token in tokens):
        return PartResult(part, "ANCHORED", None, None, None, [])
    # A ref that cites loading logic never spells the value out, so its absence
    # here proves nothing. Only finding the value somewhere else in the file
    # shows the ref points at the wrong place -- and only a hash carries that
    # weight. A filename fragment matches by coincidence: `tyrian2` hits every
    # line naming `tyrian2.c`, and a name built at runtime from a format
    # string appears nowhere at all.
    if not hash_tokens:
        return PartResult(part, "ANCHORED", None, None, None, [])
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
    kept = ("ANCHORED", "GONE", "EXTERNAL", "BINARY")
    return [
        part if part.status in kept
        else PartResult(part.part, "ANCHORED", None, None, None, [])
        for part in parts
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
    profile: dict, views, cache_dir: str, offline: bool
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
    for view in views:
        if view.pin == view.head:
            continue
        for tag in version_tag_candidates(
            profile.get("core_version"), view.repo.name
        ):
            if upstream.tag_commit(view.repo, tag, cache_dir, offline) == view.pin:
                return tag
    return None


def build_report(
    name: str, profile: dict, cache_dir: str, offline: bool = False
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
    refs = []
    for citation in collect_citations(profile):
        if citation.kind == "ref":
            entry = citation.entry
            display = str(entry.get("name") or "") or citation.field
            if citation.label:
                display += f" [{citation.label}]"
            parts = [
                RefPart(strip_repo_word(p.path, known), p.start, p.end, p.raw)
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
    # Directories the profile already cites, deepest first, to settle a bare
    # filename that several trees of one repository carry.
    cited_dirs: set[str] = set()
    for _, _, _, _, parts, _ in refs:
        for part in parts:
            directory = posixpath.dirname(part.path)
            while directory:
                cited_dirs.add(directory)
                directory = posixpath.dirname(directory)

    if select_repo(profile) is None:
        declared = str(profile.get("source") or profile.get("upstream") or "")
        report.skipped = f"unsupported host: {declared or 'none declared'}"
        return report

    stated_gone = str(profile.get("upstream_gone") or "").strip()

    try:
        views = select_views(profile, cache_dir, offline)
    except upstream.GoneError as exc:
        if stated_gone:
            # The profile says the forge is gone and the forge agrees. That is
            # a recorded fact, not an open problem: the refs describe the last
            # revision anyone can reach, and nothing further is possible.
            report.skipped = f"upstream gone (declared): {stated_gone}"
            return report
        raise
    if stated_gone and views:
        # Declared dead, yet it answered. A profile that keeps saying so stops
        # being read, so the contradiction is the finding.
        report.skipped = (
            f"upstream_gone is declared but the forge answers: {stated_gone}"
        )
        return report
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
    report.pinned_tag = detect_pinned_tag(profile, views, cache_dir, offline)

    # A profile carrying no source_ref still has a pin worth writing and a
    # version worth checking, so the revisions above are resolved first.
    if not refs:
        report.skipped = "no source_ref"
        return report

    owners: dict[tuple[str, int | None], tuple[RepoView, str]] = {}
    context: dict[str, object] = {}
    pin_trees: dict[str, list[str] | None] = {}

    def _locate(
        path: str, start: int | None = None, tokens: tuple = ()
    ) -> tuple[RepoView, str]:
        """Repository and real path carrying a cited path, HEAD before pin.

        A ref may prefix the path with the repository directory name, as it
        appears in a parent folder holding both clones: 270 parts across 21
        profiles do. That prefix is stripped only as a last resort, once the
        path as written has failed against every repository and revision.

        The pin comes before HEAD because that is the revision the ref was
        written against. `mame` cites files that both mamedev/mame and the
        libretro fork carry today, but only the upstream pin holds them; the
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

        def score(lines) -> int:
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
            line = lines[start - 1].lower()
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

        best = None
        for candidate in candidates:
            for sha_of in (lambda v: v.pin, lambda v: v.head):
                for view in views:
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
                    if rank == 3:
                        return view, candidate
                    if best is None or rank > best[0]:
                        best = (rank, view, candidate)
        return (best[1], best[2]) if best else (primary, path)

    def resolve_path(
        path: str, start: int | None = None, tokens: tuple = ()
    ) -> tuple[RepoView, str]:
        key = (path, start, tokens)
        if key not in owners:
            owners[key] = _locate(path, start, tokens)
        return owners[key]

    def _pin_tree_for(view: RepoView):
        """Tree at the revision the refs were written against, memoised."""
        key = view.repo.slug
        if key not in pin_trees:
            tree, _ = upstream.list_tree(view.repo, view.pin, cache_dir, offline)
            pin_trees[key] = tree
        return pin_trees[key]

    mute: set[tuple[str, str]] = set()

    def fetch_from(repo, sha, wanted):
        """Read a file, treating a repository that refuses as one that lacks it.

        A profile can name several repositories, and a mirror exists exactly
        because one of them stopped answering: git.eden-emu.dev returns 403 to
        anything that is not a browser. Letting the first refusal abort the
        report leaves the mirror unread and the profile unverifiable, so the
        repository is muted for the rest of the pass instead. A quota signal
        still stops everything, because continuing would only burn the rest of
        the budget on the same wall.
        """
        # Keyed by host as well as slug: a mirror carries the same slug on
        # another forge, and muting one must not silence the other.
        key = (repo.host, repo.slug)
        if key in mute:
            return None
        try:
            return upstream.fetch_file(repo, sha, wanted, cache_dir, offline)
        except upstream.RateLimitError:
            raise
        except upstream.UpstreamError as exc:
            mute.add(key)
            print(f"{name}: {repo.host}/{repo.slug} muted, {exc}", file=sys.stderr)
            return None

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

    lines_cache: dict[tuple[str, str, int | None], list[str] | None] = {}

    def fetch(which: str, path: str, start: int | None = None, tokens=(), forced=None):
        """Lines for one path at one revision, read once per run.

        The same object is handed back every time so the opcode cache can key
        on identity.
        """
        tokens = tuple(tokens)
        key = (which, path, start, tokens, forced and forced.repo.slug)
        if key not in lines_cache:
            view, actual = (
                (forced, path) if forced else resolve_path(path, start, tokens)
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

    def describe(path: str, start=None, tokens=(), forced=None):
        view, actual = (
            (forced, path) if forced else resolve_path(path, start, tuple(tokens))
        )
        slug = view.repo.slug if view is not primary else None
        return slug, upstream.raw_url(view.repo, view.head, actual), actual

    def anchor_across_views(part, tokens):
        """Judge a part against every repository that carries its path.

        A ref is only broken when it fails everywhere. `mame` cites files that
        both mamedev/mame and its libretro fork hold, with the same delimited
        token on the cited line, so no single attribution can be right for all
        of them; taking the best outcome across repositories settles it.
        """
        best = None
        for view in views:
            if fetch_from(view.repo, view.pin, part.path) is None:
                continue
            result = anchor_part(
                part,
                lambda which, path, start=None, toks=(), _v=view: fetch(
                    which, path, start, toks, _v
                ),
                rename_getter,
                lambda path, start=None, toks=(), _v=view: describe(
                    path, start, toks, _v
                ),
                tokens,
            )
            rank = STATUS_ORDER.index(result.status)
            if best is None or rank < best[0]:
                best = (rank, result)
        return best[1] if best else anchor_part(
            part, fetch, rename_getter, describe, tokens
        )

    # Comparing a revision with itself anchors every ref whatever it cites, so
    # a profile already sitting on HEAD is judged on self-consistency instead.
    self_check = bool(report.pinned_tag) or primary.pin == primary.head
    if self_check:
        staged = [
            (entry_name, ref, citation, reconcile_self_check([
                verify_at_pin(
                    part, fetch(PIN, part.path, part.start, tokens), tokens, hashes
                )
                for part in ref_parts
            ]))
            for entry_name, ref, tokens, hashes, ref_parts, citation in refs
        ]
    else:
        staged = [
            (entry_name, ref, citation, [
                anchor_across_views(part, tokens)
                for part in ref_parts
            ])
            for entry_name, ref, tokens, hashes, ref_parts, citation in refs
        ]

    shifts = dominant_shifts([p for _, _, _, parts in staged for p in parts])
    for entry_name, ref, citation, parts in staged:
        parts = [resolve_by_shift(p, shifts) for p in parts]
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
    entry: EntryReport, statuses
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


def _run_after_moves(parts, moves: dict[int, tuple[int, int, str | None]]) -> str:
    """The prose run as it reads once its moved ranges are rewritten."""
    new_path = next(
        (move[2] for move in moves.values() if move[2]), None
    )
    ranges = []
    for index, part in enumerate(parts):
        if index in moves:
            start, end, _ = moves[index]
            ranges.append(f"{start}" if end == start else f"{start}-{end}")
        else:
            ranges.append(part.raw)
    return f"{new_path or parts[0].path}:{','.join(ranges)}"


def _apply_prose_edits(
    text: str, jobs: list[tuple[Citation, dict]]
) -> tuple[str, list[str], list[str]]:
    """Rewrite prose citation tokens in place, nothing else.

    Each run is located as the unique physical line carrying the scalar line
    it sits on. Two candidate lines, or none, means the write cannot be
    proved right, so the run is left alone and reported. All replacements of
    one line are applied together, right to left, so the spans measured on
    the original text stay valid.
    """
    lines = text.splitlines()
    trailing = "\n" if text.endswith("\n") else ""
    file_edits: dict[int, list[tuple[int, int, str]]] = {}
    value_edits: dict[tuple[int, object], dict[int, list]] = {}
    holders: dict[tuple[int, object], tuple] = {}
    applied: list[str] = []
    left: list[str] = []

    for citation, moves in jobs:
        value = str(citation.holder[citation.key])
        value_lines = value.splitlines()
        if citation.line >= len(value_lines):
            left.append(f"{citation.field}: {citation.ref} (scalar changed)")
            continue
        replacements = []
        for index, (start, end, _) in moves.items():
            lo, hi = citation.spans[index]
            replacements.append(
                (lo, hi, f"{start}" if end == start else f"{start}-{end}")
            )
        new_path = next((m[2] for m in moves.values() if m[2]), None)
        if new_path:
            replacements.append((*citation.path_span, new_path))
        target = value_lines[citation.line]
        hits = [i for i, line in enumerate(lines) if target and target in line]
        if len(hits) == 1:
            offset = lines[hits[0]].index(target)
            file_edits.setdefault(hits[0], []).extend(
                (offset + lo, offset + hi, new) for lo, hi, new in replacements
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
                i for i, line in enumerate(lines) if pattern.search(line)
            ]
            if (
                len(run_hits) != 1
                or len(pattern.findall(lines[run_hits[0]])) != 1
            ):
                left.append(
                    f"{citation.field}: {citation.ref} "
                    f"({len(hits)} lines carry its sentence)"
                )
                continue
            low = pattern.search(lines[run_hits[0]]).start()
            file_edits.setdefault(run_hits[0], []).append(
                (low, low + len(citation.ref),
                 _run_after_moves(citation.parts, moves))
            )
        slot = (id(citation.holder), citation.key)
        holders[slot] = (citation.holder, citation.key)
        value_edits.setdefault(slot, {}).setdefault(citation.line, []).extend(
            replacements
        )
        applied.append(
            f"{citation.field}: {citation.ref} -> "
            f"{_run_after_moves(citation.parts, moves)}"
        )

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


def blocks_the_pin(report: ProfileReport, accept_changed: bool = False) -> int:
    """What would keep source_commit where it is after a recale.

    Two kinds. A ref the writer never regenerates, annotated or under a mode
    key, whose parts have moved. And a prose run whose tokens cannot be
    located well enough to rewrite, which stays describing the pinned
    revision whatever else moves. Either one makes bump_commit refuse, so
    either one has to stop the recale as well.
    """
    movable = REBASE_STATUSES + (("CHANGED",) if accept_changed else ())
    blocked = pending_recale(report, accept_changed)
    for entry in report.entries or []:
        if entry.kind != "prose" or _prose_moves(entry, movable):
            continue
        if any(
            part.status in movable
            and part.start is not None
            and (
                (part.start, part.end) != (part.part.start, part.part.end)
                or part.new_path
            )
            for part in entry.parts
        ):
            blocked += 1
    return blocked


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
    if blocks_the_pin(report, accept_changed):
        # Something here will not move: an annotated ref, one under a mode
        # key, or a prose run this pass cannot rewrite without guessing.
        # bump_commit will refuse while it stands, and recaling the rest
        # would leave the profile describing two revisions at once. All or
        # nothing means the pin too, not only the refs.
        return []
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    citations = collect_citations(document)
    applied: list[str] = []
    cursor = 0
    pos = 0
    prose_jobs: list[tuple[Citation, dict]] = []

    for entry in report.entries:
        citation, pos = _match_citation(citations, pos, entry)
        if citation is None:
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

    text, prose_applied, _ = _apply_prose_edits(text, prose_jobs)
    applied.extend(prose_applied)
    if applied:
        apply_edit(path, text, document)
    return applied


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
    pending = 0
    for entry in report.entries or []:
        if entry.kind == "prose":
            continue
        if _is_rewritable(entry.source_ref) and not entry.name.endswith("]"):
            continue
        pending += sum(
            1
            for part in entry.parts
            if part.status in movable
            and part.start is not None
            and _rendered_part(part) != _original_part(part)
        )
    if text is None:
        return pending

    document = yaml.safe_load(text)
    pool: dict[tuple[str, str], int] = {}
    for citation in collect_citations(document):
        if citation.kind == "prose":
            slot = (citation.field, _citation_key(citation.ref))
            pool[slot] = pool.get(slot, 0) + 1
    for entry in report.entries or []:
        if entry.kind != "prose":
            continue
        moves = _prose_moves(entry, movable)
        if not moves:
            # Either nothing has to move, or the run cannot be written
            # without guessing; the second case still blocks the pin.
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
        rendered = _run_after_moves([p.part for p in entry.parts], moves)
        if _citation_key(rendered) == _citation_key(entry.source_ref):
            continue
        slot = (entry.field, _citation_key(rendered))
        if pool.get(slot, 0) > 0:
            pool[slot] -= 1
            continue
        pending += 1
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
    text = path.read_text(encoding="utf-8")
    if pending_recale(report, accept_changed, text):
        return False
    document = yaml.safe_load(text)
    if document.get("source_commit") == report.head:
        # Rewriting the pin to the value it already holds is not a bump, and
        # announcing it buries the profiles that did move.
        return False
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


def _git_history(path: Path) -> list[str]:
    """Commits touching the profile, newest first, empty outside a repo."""
    result = subprocess.run(
        ["git", "log", "--format=%H", "--", path.name],
        cwd=path.parent, capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return []
    return result.stdout.split()


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


def _scalar_values(document: dict) -> dict[str, str]:
    """String scalars of the document, keyed by field path."""
    return {
        field: value
        for kind, field, _, _, value in _walk_document(document)
        if kind == "str"
    }


def _writing_pin(
    revisions: list[tuple[str, dict]], intro_sha: str, field: str
) -> str | None:
    """Pin recorded at the introducing commit, or first recorded after it.

    The backfill resolved missing pins from profiled_date, the writing time
    of the profile, so the first value ever recorded stands for the scalars
    that predate it.
    """
    index = next(
        (i for i, (sha, _) in enumerate(revisions) if sha == intro_sha), None
    )
    if index is None:
        return None
    for position in range(index, -1, -1):
        value = revisions[position][1].get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _resolve_at(
    repo, sha: str, path: str, cache_dir: str, offline: bool
) -> tuple[str, object]:
    """("found", (path, lines)) or ("unclear"|"missing", reason).

    Prose often cites a bare filename; the tree at the revision resolves it
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
    part: RefPart, pairs, cache_dir: str, offline: bool
) -> tuple[str, object] | None:
    """One range, anchored from its writing revision to the current pin."""
    unclear = None
    for repo, written, current in pairs:
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
    return "skip", f"{part.path} absent at the writing revision"


def realign_prose(
    path: Path, cache_dir: str, offline: bool = False, dry_run: bool = False
) -> list[str]:
    """Recale prose runs from the pin their text was written at.

    A prose run written under an older pin describes that revision, and
    anchoring it from the current pin would faithfully track the wrong
    content: the cited line holds someone else's code there. The writing pin
    is read from the profile's own history, at the commit that introduced
    the scalar's current text.
    """
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        return []
    citations = [c for c in collect_citations(document) if c.kind == "prose"]
    if not citations:
        return []
    repos = [
        (field, upstream.parse_repo(str(document.get(field) or "")))
        for field in ("source", "upstream")
    ]
    repos = [(field, repo) for field, repo in repos if repo is not None]
    if not repos:
        return []
    history = _git_history(path)
    if not history:
        return []

    current_values = _scalar_values(document)
    fields = {citation.field for citation in citations}
    alive = dict.fromkeys(fields, True)
    intro: dict[str, str | None] = dict.fromkeys(fields)
    revisions: list[tuple[str, dict]] = []
    for sha in history:
        if not any(alive.values()):
            break
        past = _git_file_at(path, sha)
        if past is None:
            break
        revisions.append((sha, past))
        values = _scalar_values(past)
        for field in fields:
            if not alive[field]:
                continue
            if values.get(field) == current_values.get(field):
                intro[field] = sha
            else:
                alive[field] = False

    messages: list[str] = []
    jobs: list[tuple[Citation, dict]] = []
    for citation in citations:
        intro_sha = intro.get(citation.field)
        if intro_sha is None:
            # The scalar is not committed yet: written now, under this pin.
            continue
        pairs = []
        for pin_field, repo in repos:
            current = document.get(f"{pin_field}_commit")
            if not isinstance(current, str) or not current:
                continue
            written = _writing_pin(revisions, intro_sha, f"{pin_field}_commit")
            if written and written != current:
                pairs.append((repo, written, current))
        if not pairs:
            continue
        moves: dict[int, tuple[int, int, str | None]] = {}
        blocked: list[str] = []
        for index, part in enumerate(citation.parts):
            outcome = _realign_part(part, pairs, cache_dir, offline)
            if outcome is None:
                continue
            state, payload = outcome
            if state == "ok":
                start, end = payload
                moves[index] = (start, end, None)
            else:
                blocked.append(payload)
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
            f"{_run_after_moves(citation.parts, moves)}"
            for citation, moves in jobs
        )
        return messages
    new_text, applied, left = _apply_prose_edits(text, jobs)
    messages.extend(applied)
    messages.extend(f"left in place: {item}" for item in left)
    if applied:
        apply_edit(path, new_text, document)
    return messages


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
    parser.add_argument(
        "--report-dir",
        default="reports",
        help="directory for the markdown report (default: reports)",
    )
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
        "--realign-prose",
        action="store_true",
        help="recale prose citations from the pin their text was written at",
    )
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
    if not (args.rebase_refs or args.bump_commit):
        return
    both = args.rebase_refs and args.bump_commit
    with tempfile.TemporaryDirectory() as scratch:
        # Always work on a copy. A dry run reports what it left there; a real
        # run promotes it. Asking for both writes makes the pass atomic: the
        # pin has to follow the refs or neither moves, because a profile whose
        # refs describe one revision and whose pin names another is exactly
        # what the all-or-nothing rule exists to prevent.
        target = Path(scratch) / path.name
        target.write_bytes(path.read_bytes())
        recale, bumped = (
            ("would recale ", "would set source_commit ->") if args.dry_run
            else ("", "source_commit ->")
        )
        applied = []
        if args.rebase_refs and not report.skipped:
            applied = rebase_refs(target, report, args.accept_changed)
        moved = bool(args.bump_commit) and bump_commit(
            target, report, args.accept_changed
        )
        if both and applied and not moved:
            print(
                f"{name}: refs recaled but the pin will not follow, so nothing "
                "was written; the prose or an annotated ref has to move first",
                file=sys.stderr,
            )
            return
        for line in applied:
            print(f"{name}: {recale}{line}")
        if moved:
            print(f"{name}: {bumped} {report.head[:7]}")
        if not args.dry_run and (applied or moved):
            path.write_bytes(target.read_bytes())


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
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    selected = select_profiles(profiles, args)
    _check_quota(len(selected), args.offline)

    writes = (
        args.backfill_commits or args.rebase_refs or args.bump_commit
        or args.realign_prose
    )
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

    if args.realign_prose:
        for name in selected:
            profile_path = Path(args.emulators_dir) / f"{name}.yml"
            if not profile_path.is_file():
                continue
            try:
                for line in realign_prose(
                    profile_path, args.cache_dir, args.offline, args.dry_run
                ):
                    print(f"{name}: {line}")
            except upstream.RateLimitError:
                raise
            except upstream.UpstreamError as exc:
                print(f"{name}: {exc}", file=sys.stderr)
            except YamlWriteError as exc:
                print(f"{name}: write refused: {exc}", file=sys.stderr)
        return

    reports = []
    for name, profile in selected.items():
        try:
            report = build_report(name, profile, args.cache_dir, args.offline)
        except upstream.RateLimitError:
            raise
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
        target = Path(args.report_dir) / f"profile-sync-{date.today().isoformat()}.md"
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
