"""Write a settled field into one entry of a profile, and nothing else.

The profile is edited as text, so its comments, order and quoting stay as
the maintainer wrote them. Every edit is checked by parsing the result: the
edited entry must equal the old one with the new fields, and every other
part of the profile must parse to what it did before. An edit that cannot
hold both is refused (ProfileEditError), never written.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ITEM = re.compile(r"^(?P<indent>\s*)- ")
KEY = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z_][A-Za-z0-9_]*):(?P<rest>.*)$")
# Where a new key goes: after the first of these the entry has, else last.
ANCHORS = {
    "required": ("name",),
    "hle_fallback": ("required", "name"),
    "path": ("name",),
    "aliases": ("path", "name"),
    "validation": ("sha1", "md5", "crc32", "size", "name"),
    "on_mismatch": ("validation", "sha1", "md5", "crc32", "size", "name"),
    "found_by": ("path", "name"),
}


class ProfileEditError(ValueError):
    """An edit the profile's layout does not allow to make safely."""


def scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(scalar(v) for v in value) + "]"
    raise ProfileEditError(f"no scalar form for {value!r}")


def item_spans(lines: list[str]) -> list[tuple[int, int, int]]:
    """(first line, end line, item indent) of each item of the top-level files: list."""
    try:
        start = next(i for i, line in enumerate(lines) if line.rstrip() == "files:")
    except StopIteration as exc:
        raise ProfileEditError("no top-level files: list") from exc
    spans: list[tuple[int, int, int]] = []
    indent: int | None = None
    current: int | None = None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        width = len(line) - len(line.lstrip(" "))
        if width == 0 and not line.startswith("-"):
            end = i
            break
        match = ITEM.match(line)
        if match and (indent is None or width == indent):
            indent = width
            if current is not None:
                spans.append((current, i, indent))
            current = i
    if current is not None:
        spans.append((current, end, indent or 0))
    # An item ends at its last line of content: the comments and blank lines
    # before the next item belong to that item.
    trimmed = []
    for first, stop, width in spans:
        last = stop
        while last > first + 1 and (not lines[last - 1].strip() or lines[last - 1].strip().startswith("#")):
            last -= 1
        trimmed.append((first, last, width))
    return trimmed


def key_lines(lines: list[str], first: int, stop: int, key_indent: int) -> dict[str, tuple[int, int]]:
    """key -> (line, end line) for each key of one item, its continuation lines included."""
    keys: dict[str, tuple[int, int]] = {}
    order: list[tuple[str, int]] = []
    for i in range(first, stop):
        # The item's first line carries the dash where its first key's indent is.
        line = " " * key_indent + lines[i][key_indent:] if i == first else lines[i]
        match = KEY.match(line)
        if match and len(match["indent"]) == key_indent:
            order.append((match["key"], i))
    for position, (key, start) in enumerate(order):
        end = order[position + 1][1] if position + 1 < len(order) else stop
        while end > start + 1 and (not lines[end - 1].strip() or lines[end - 1].strip().startswith("#")):
            end -= 1
        keys[key] = (start, end)
    return keys


def _render(key: str, value: object, indent: int, block: bool = False) -> list[str]:
    """One key as lines. A list keeps the block style it was written in."""
    pad = " " * indent
    if isinstance(value, dict):
        return [f"{pad}{key}:"] + [f"{pad}  {k}: {scalar(v)}" for k, v in value.items()]
    if block and isinstance(value, list):
        return [f"{pad}{key}:"] + [f"{pad}  - {scalar(v)}" for v in value]
    return [f"{pad}{key}: {scalar(value)}"]


def set_fields(text: str, index: int, updates: dict[str, object]) -> str:
    """The profile with these keys of files[index] set, the rest untouched."""
    before = yaml.safe_load(text)
    entries = before.get("files") or []
    if not 0 <= index < len(entries):
        raise ProfileEditError(f"no files[{index}]")
    lines = text.splitlines()
    spans = item_spans(lines)
    if len(spans) != len(entries):
        raise ProfileEditError(f"{len(spans)} items read as text, {len(entries)} parsed")
    first, stop, item_indent = spans[index]
    key_indent = item_indent + 2
    for key, value in updates.items():
        keys = key_lines(lines, first, stop, key_indent)
        if key in keys:
            start, end = keys[key]
            rendered = _render(key, value, key_indent, block=lines[start].rstrip().endswith(":"))
            if start == first:
                raise ProfileEditError(f"files[{index}]: {key} is the item's first key")
            lines[start:end] = rendered
            stop += len(rendered) - (end - start)
            continue
        rendered = _render(key, value, key_indent)
        anchor = next((keys[a][1] for a in ANCHORS.get(key, ()) if a in keys), None)
        at = anchor if anchor is not None else stop
        lines[at:at] = rendered
        stop += len(rendered)
    out = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    after = yaml.safe_load(out)
    expected = {**entries[index], **updates}
    if after.get("files", [None] * (index + 1))[index] != expected:
        raise ProfileEditError(f"files[{index}]: the edit does not parse to the intended entry")
    rest_before = {k: v for k, v in before.items() if k != "files"}
    rest_after = {k: v for k, v in after.items() if k != "files"}
    others_before = [e for i, e in enumerate(entries) if i != index]
    others_after = [e for i, e in enumerate(after.get("files") or []) if i != index]
    if rest_before != rest_after or others_before != others_after:
        raise ProfileEditError(f"files[{index}]: the edit changes another part of the profile")
    return out


def write_fields(path: Path, index: int, updates: dict[str, object]) -> bool:
    """Apply the edit to the file. False when it changes nothing."""
    text = path.read_text(encoding="utf-8")
    out = set_fields(text, index, updates)
    if out == text:
        return False
    path.write_text(out, encoding="utf-8")
    return True
