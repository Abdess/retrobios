"""The installer event schema against EVENT_KEYS."""

from __future__ import annotations

from jsonschema import Draft202012Validator

import core.paths
from installer_build import eventschema
from schemas.validators import load_json


def event_schema_errors() -> list[str]:
    """install-events.schema.json is EVENT_KEYS written out, and a valid schema."""
    path = core.paths.REPO_ROOT / "schemas" / eventschema.OUTPUT.name
    label = path.relative_to(core.paths.REPO_ROOT).as_posix()
    if not path.is_file():
        return [f"{label}: missing, run python scripts/generate_event_schema.py"]
    if path.read_text(encoding="utf-8") != eventschema.render(
        eventschema.build_schema()
    ):
        return [f"{label}: differs from EVENT_KEYS in install.py, run "
                "python scripts/generate_event_schema.py"]
    Draft202012Validator.check_schema(load_json(path))
    return []
