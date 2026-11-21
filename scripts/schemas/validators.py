"""The schema files under schemas/, their validators and the error lines they give."""

from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

import core.paths


SCHEMAS = core.paths.REPO_ROOT / "schemas"


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def json_object(path: Path) -> dict:
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a JSON object")
    return data


def schema_validator(name: str) -> Draft202012Validator:
    schema = load_json(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def defs_validator(name: str, definition: str) -> Draft202012Validator:
    """A validator for one $defs entry of a schema file."""
    schema = json_object(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        {**schema, "$ref": f"#/$defs/{definition}"}, format_checker=FormatChecker()
    )


def schema_errors(validator: Draft202012Validator, data: object, label: str) -> list[str]:
    out: list[str] = []
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.path)):
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        out.append(f"{label}:{location}: {error.message}")
    return out


def unchecked_formats() -> list[str]:
    """Formats the schemas declare that this jsonschema install cannot check.

    date-time and uri need the format extras. Without them the ten format
    constraints of the published schemas were accepted unread.
    """
    used = {
        match
        for path in SCHEMAS.glob("*.json")
        for match in re.findall(r'"format"\s*:\s*"([^"]+)"', path.read_text(encoding="utf-8"))
    }
    return sorted(used - set(FormatChecker().checkers))


def format_errors() -> list[str]:
    """jsonschema skips a format it has no checker for: say so, and fail."""
    return [
        f"no checker for format {name}: install \"jsonschema[format-nongpl]\""
        for name in unchecked_formats()
    ]
