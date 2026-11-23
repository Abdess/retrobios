"""Every citation a profile makes, in source_ref fields and in prose, with the tokens that identify it."""

from __future__ import annotations

import bisect
import os
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass

import yaml

from core.hashing import parse_hash_list
from model.citations import document_citations, known_repositories
from model.sourceref import RefPart, prose_runs, ref_role


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
        for field_name in HASH_FIELDS:
            for v in parse_hash_list(source.get(field_name)):
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


def anchor_tokens(entry: dict) -> list[str]:
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
            for _, path_span, run_spans, parts, run, _ in prose_runs(comment, known):
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
    known = known_repositories(document)
    citations = [
        Citation(
            field=found.field, kind=found.kind, ref=found.ref,
            entry=found.holder if found.kind == "ref" and isinstance(found.holder, dict) else None,
            holder=found.holder, key=found.key, label=found.label, line=found.line,
            path_span=found.path_span, spans=found.spans, parts=found.parts,
            wrapped=bool(found.joined_at), joined_at=found.joined_at,
        )
        for found in document_citations(document, known)
    ]
    if text is not None:
        citations.extend(comment_citations(text, known))
    return citations


def citation_key(ref: str) -> str:
    """A citation compared without the spacing the author chose.

    A recale rewrites the located tokens and leaves the sentence alone, so
    `a.c:228, 1439-1443` keeps its space while the rendered form drops it.
    They are the same citation, and comparing them literally makes a run
    that was written look unwritten, which holds the pin back for ever.
    """
    return re.sub(r"\s+", "", ref)
