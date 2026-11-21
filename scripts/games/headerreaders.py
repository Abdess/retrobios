"""The readers of games/headers.yml and the values each can return."""

from __future__ import annotations


def header_readers(headers: dict) -> dict[str, dict]:
    """Every reader of games/headers.yml by id, over all its systems."""
    readers: dict[str, dict] = {}
    for system in (headers.get("systems") or {}).values():
        readers.update(system.get("readers") or {})
    return readers


def reader_answers(reader: dict, field: str | None = None) -> set[object] | None:
    """The labels and values a reader can return, None when any string can
    be (a serial or product id read as it stands)."""
    if field:
        spec = (reader.get("fields") or {}).get(field) or {}
        return {v for k, v in spec.items() if k not in ("encoding",) and isinstance(v, str)}
    decode = reader.get("decode") or {}
    if decode.get("kind") == "serial":
        return None
    answers: set[object] = set()
    for row in decode.get("values") or []:
        answers.update(row[k] for k in ("value", "label") if k in row)
    for key in ("then", "otherwise"):
        branch = decode.get(key)
        if isinstance(branch, dict) and "label" in branch:
            answers.add(branch["label"])
        elif isinstance(branch, str):
            answers.add(branch)
    return answers
