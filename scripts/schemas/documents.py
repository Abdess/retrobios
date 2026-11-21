"""Generated JSON documents against their schemas: the database and the site API."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import core.paths
from schemas.validators import load_json, schema_errors, schema_validator


def validate_json_files(
    paths: list[Path],
    schema_name: str,
    semantic_check: Callable[[Path, dict], list[str]] | None = None,
) -> list[str]:
    validator = schema_validator(schema_name)
    out: list[str] = []
    for path in paths:
        try:
            data = load_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            out.append(f"{path.relative_to(core.paths.REPO_ROOT)}: {exc}")
            continue
        validation_errors = schema_errors(validator, data, str(path.relative_to(core.paths.REPO_ROOT)))
        out.extend(validation_errors)
        # Every schema a semantic check follows describes an object.
        if not validation_errors and semantic_check is not None and isinstance(data, dict):
            out.extend(semantic_check(path, data))
    return out


def semantic_envelope_checks(path: Path, document: dict) -> list[str]:
    if document.get("count") != len(document.get("items", [])):
        return [f"{path.relative_to(core.paths.REPO_ROOT)}: count does not equal len(items)"]
    return []


def semantic_database_checks(database: dict) -> list[str]:
    out: list[str] = []
    files = database.get("files", {})
    if database.get("total_files") != len(files):
        out.append("database.json: total_files does not equal len(files)")
    if database.get("total_size") != sum(entry.get("size", 0) for entry in files.values()):
        out.append("database.json: total_size does not equal the file-size sum")
    # One path holds one content. Two entries naming the same path means one
    # of them declares a hash the file at that path does not have.
    owners: dict[str, str] = {}
    for sha1, entry in files.items():
        if entry.get("sha1") != sha1:
            out.append(f"database.json: files/{sha1}: key and sha1 differ")
        path = entry.get("path", "")
        if not path:
            continue
        first = owners.setdefault(path, sha1)
        if first != sha1:
            out.append(
                f"database.json: {path} is claimed by {first} and {sha1}"
            )
    return out
