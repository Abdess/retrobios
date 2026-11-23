"""Every source_ref and prose citation a profile document carries, read the one way every reader shares."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from core import upstream
from model.profilerepos import declared_repositories
from model.sourceref import RefPart, prose_runs, ref_prose_text, source_ref_values


@dataclass(frozen=True)
class DocumentCitation:
    """One citation of a document and where it is written.

    kind is "ref" for a source_ref value, whose ref is one labelled string
    of it, and "prose" for a file:line run inside a string scalar or inside
    the annotations of a source_ref, which carries its spans and parts.
    """

    kind: str
    field: str
    holder: object
    key: object
    ref: str
    label: str = ""
    line: int = 0
    path_span: tuple[int, int] = (0, 0)
    spans: tuple[tuple[int, int], ...] = ()
    parts: tuple[RefPart, ...] = ()
    joined_at: int = 0


def known_repositories(document: dict) -> frozenset[str]:
    """The lowercased names of the repositories the document declares.

    A name written before a path in prose (`BAM_FPloader FPLoader.cpp:259`)
    is the repository the path reads in, not part of the path.
    """
    return frozenset(
        repo.name.lower()
        for _, _, url in declared_repositories(document)
        if (repo := upstream.parse_repo(url)) is not None
    )


def list_segments(items: list) -> list[object]:
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


def walk_document(
    node: object, where: str = ""
) -> Iterator[tuple[str, str, dict | list, object, Any]]:
    """Every citation carrier of the document, with its holder and field path.

    Yields ("ref", field, holder, key, value) for each source_ref key and
    ("str", field, holder, key, value) for every other string scalar, list
    items included. One walker builds every field path, so the paths that
    name a scalar today still name it when another pass looks it up at
    another revision.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            spot = f"{where}.{key}" if where else str(key)
            if key == "source_ref":
                yield "ref", spot, node, key, value
            elif isinstance(value, str):
                yield "str", spot, node, key, value
            else:
                yield from walk_document(value, spot)
    elif isinstance(node, list):
        segments = list_segments(node)
        for index, item in enumerate(node):
            spot = f"{where}[{segments[index]}]"
            if isinstance(item, str):
                yield "str", spot, node, index, item
            else:
                yield from walk_document(item, spot)


def _prose(
    field: str, holder: object, key: object, text: str, known: frozenset[str]
) -> Iterator[DocumentCitation]:
    for line, path_span, spans, parts, run, joined_at in prose_runs(text, known):
        yield DocumentCitation(
            kind="prose", field=field, holder=holder, key=key, ref=run,
            line=line, path_span=path_span, spans=spans, parts=parts,
            joined_at=joined_at,
        )


def document_citations(
    document: dict, known: frozenset[str] | None = None
) -> Iterator[DocumentCitation]:
    """Every citation the document carries, in document order.

    A source_ref key anywhere in the document is a structured citation, and
    the annotations of a string source_ref are prose. Every other string
    scalar is scanned for prose runs, a prefix naming a declared repository
    read as that repository.
    """
    if known is None:
        known = known_repositories(document)
    for kind, field_name, holder, key, value in walk_document(document):
        if kind == "ref":
            for label, ref in source_ref_values(value):
                yield DocumentCitation(
                    kind="ref", field=field_name, holder=holder, key=key,
                    ref=ref, label=label,
                )
            if isinstance(value, str):
                yield from _prose(field_name, holder, key, ref_prose_text(value), known)
            continue
        yield from _prose(field_name, holder, key, value, known)
