"""Moves of citation locations written inside YAML scalars and comments."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

import yaml

from model.sourceref import RefPart
from profiling.citations import Citation


_RANGE_TOKEN_RE = re.compile(r"\d+(?:-\d+)?")


def run_after_moves(
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


def _scalar(holder: object, key: object) -> object:
    """The value a citation's holder keeps under its key."""
    if isinstance(holder, list) and isinstance(key, int):
        return holder[key]
    if isinstance(holder, dict):
        return holder[key]
    raise TypeError(f"no scalar under {key!r} in a {type(holder).__name__}")


def set_scalar(holder: object, key: object, value: str) -> None:
    """Replace the value a citation's holder keeps under its key."""
    if isinstance(holder, dict):
        holder[key] = value
        return
    if not isinstance(holder, list) or not isinstance(key, int):
        raise TypeError(f"no scalar under {key!r} in a {type(holder).__name__}")
    holder[key] = value


Span = tuple[int, int, str]


@dataclass
class _ProseEdits:
    """Replacements gathered over a file and its loaded scalars, and what
    was written or left."""

    lines: list[str]
    windows: dict[tuple[int, object], tuple[int, int]]
    whole: tuple[int, int]
    file_edits: dict[int, list[Span]] = field(default_factory=dict)
    value_edits: dict[tuple[int, object], dict[int, list[Span]]] = field(default_factory=dict)
    holders: dict[tuple[int, object], tuple[object, object]] = field(default_factory=dict)
    applied: list[str] = field(default_factory=list)
    left: list[str] = field(default_factory=list)


def _prose_replacements(
    citation: Citation, moves: dict[int, tuple[int, int, str | None]]
) -> list[Span]:
    """The tokens of one run a recale rewrites, measured on its line."""
    replacements: list[Span] = [
        (*citation.spans[index], f"{start}" if end == start else f"{start}-{end}")
        for index, (start, end, _) in moves.items()
    ]
    new_path = next((m[2] for m in moves.values() if m[2]), None)
    if new_path:
        replacements.append((*citation.path_span, new_path))
    return replacements


def _edit_comment_run(
    edits: _ProseEdits, citation: Citation, replacements: list[Span], recaled: str
) -> None:
    # The comment is read again from the text being written: a run
    # whose tokens no longer sit at the collected offsets is left.
    lines = edits.lines
    line = lines[citation.line] if citation.line < len(lines) else ""
    expected = [p.raw for p in citation.parts] + [citation.ref.split(":", 1)[0]]
    spans = list(citation.spans) + [citation.path_span]
    if any(line[lo:hi] != token for (lo, hi), token in zip(spans, expected)):
        edits.left.append(f"{citation.field}: {citation.ref} (comment changed)")
        return
    edits.file_edits.setdefault(citation.line, []).extend(replacements)
    edits.applied.append(f"{citation.field}: {citation.ref} -> {recaled}")


def _split_by_line(
    citation: Citation, value_lines: list[str], last: int, replacements: list[Span]
) -> dict[int, list[Span]] | None:
    """Replacements by the scalar line holding them, None when a token
    spans the line break."""
    # A wrapped run puts its spans back on the two scalar lines it
    # joined: playdiaemu wrote `content.rs` and `:111-199` one line apart.
    by_line: dict[int, list[Span]] = {}
    for lo, hi, new in replacements:
        if citation.wrapped and lo >= citation.joined_at:
            following = value_lines[last]
            indent = len(following) - len(following.lstrip())
            shift = indent - citation.joined_at
            by_line.setdefault(last, []).append((lo + shift, hi + shift, new))
        elif citation.wrapped and hi > citation.joined_at:
            return None
        else:
            by_line.setdefault(citation.line, []).append((lo, hi, new))
    return by_line


def _lines_apart(located: dict[int, int | None], first: int, last: int) -> bool:
    """Whether the two lines of a wrapped run are not found together."""
    if None in located.values():
        return True
    if len(located) != 2:
        return False
    low, high = located[first], located[last]
    return low is None or high is None or high != low + 1


def _edit_folded_run(
    edits: _ProseEdits, citation: Citation, value_lines: list[str],
    window: tuple[int, int], recaled: str,
) -> bool:
    """Rewrite a run whose scalar is folded, False when it is left."""
    # A folded scalar has no physical line carrying its logical one.
    # The run itself is a single word, which folding never breaks:
    # when the whole file carries it exactly once, that occurrence
    # is the citation, and the run is rewritten as one token. The
    # match is delimited, or `x.c:481` would also hit inside a
    # neighbouring `x.c:481-482`.
    lines = edits.lines
    pattern = re.compile(
        rf"(?<![\w/.-]){re.escape(citation.ref)}(?![\w-])"
    )
    run_hits = [
        i for i in range(window[0], min(window[1], len(lines) - 1) + 1)
        if pattern.search(lines[i])
    ]
    hit = pattern.search(lines[run_hits[0]]) if len(run_hits) == 1 else None
    if hit is None or len(pattern.findall(lines[run_hits[0]])) != 1:
        carriers = sum(
            1 for line in lines[window[0]:window[1] + 1]
            if value_lines[citation.line] and value_lines[citation.line] in line
        )
        edits.left.append(
            f"{citation.field}: {citation.ref} "
            f"({carriers} lines carry its sentence)"
        )
        return False
    low = hit.start()
    edits.file_edits.setdefault(run_hits[0], []).append(
        (low, low + len(citation.ref), recaled)
    )
    return True


def _edit_scalar_run(
    edits: _ProseEdits, citation: Citation, replacements: list[Span], recaled: str
) -> None:
    value = str(_scalar(citation.holder, citation.key))
    value_lines = value.splitlines()
    last = citation.line + (1 if citation.wrapped else 0)
    if last >= len(value_lines):
        edits.left.append(f"{citation.field}: {citation.ref} (scalar changed)")
        return
    by_line = _split_by_line(citation, value_lines, last, replacements)
    if by_line is None:
        edits.left.append(f"{citation.field}: {citation.ref} (a token spans the line break)")
        return
    window = edits.windows.get((id(citation.holder), citation.key), edits.whole)
    located = {
        number: _unique_line(edits.lines, value_lines[number], window)
        for number in by_line
    }
    if citation.wrapped and _lines_apart(located, citation.line, last):
        edits.left.append(
            f"{citation.field}: {citation.ref} "
            "(wrapped, and its two lines are not found together in the file)"
        )
        return
    placed = {number: hit for number, hit in located.items() if hit is not None}
    if len(placed) == len(located):
        for number, line_edits in by_line.items():
            hit = placed[number]
            offset = edits.lines[hit].index(value_lines[number])
            edits.file_edits.setdefault(hit, []).extend(
                (offset + lo, offset + hi, new) for lo, hi, new in line_edits
            )
    elif not _edit_folded_run(edits, citation, value_lines, window, recaled):
        return
    slot = (id(citation.holder), citation.key)
    edits.holders[slot] = (citation.holder, citation.key)
    for number, line_edits in by_line.items():
        edits.value_edits.setdefault(slot, {}).setdefault(number, []).extend(line_edits)
    edits.applied.append(f"{citation.field}: {citation.ref} -> {recaled}")


def apply_prose_edits(
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
    edits = _ProseEdits(
        lines,
        scalar_windows(text, document) if document is not None else {},
        (0, len(lines) - 1),
    )

    for citation, moves in jobs:
        replacements = _prose_replacements(citation, moves)
        recaled = run_after_moves(citation.parts, moves, citation.ref)
        if citation.in_comment:
            _edit_comment_run(edits, citation, replacements, recaled)
        else:
            _edit_scalar_run(edits, citation, replacements, recaled)

    for number, spans in edits.file_edits.items():
        lines[number] = _replace_spans(lines[number], spans)
    for slot, by_line in edits.value_edits.items():
        holder, key = edits.holders[slot]
        value = str(_scalar(holder, key))
        value_lines = value.splitlines()
        for line_number, spans in by_line.items():
            value_lines[line_number] = _replace_spans(value_lines[line_number], spans)
        set_scalar(holder, key, "\n".join(value_lines) + (
            "\n" if value.endswith("\n") else ""
        ))
    return "\n".join(lines) + trailing, edits.applied, edits.left


def _replace_spans(line: str, replacements: list[tuple[int, int, str]]) -> str:
    """Apply span replacements measured on the original line."""
    for lo, hi, new in sorted(replacements, reverse=True):
        line = line[:lo] + new + line[hi:]
    return line
