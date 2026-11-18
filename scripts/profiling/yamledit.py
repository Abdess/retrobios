"""Line edits of a profile YAML that keep its layout and comments, checked against the parsed result."""

from __future__ import annotations

from pathlib import Path

import yaml



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
        if after is None:
            raise YamlWriteError("version_basis: core_version not found to write it after")
        lines[after[1]:after[1]] = _render_basis(basis)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


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
