"""Parsing the repository's YAML sources, naming the file a syntax error is in."""

from __future__ import annotations

from typing import Any, TextIO

try:
    import yaml
except ImportError:
    yaml = None

from core.cli import SourceUnreadable
from model.safeparse import yaml_load


def source_yaml(stream: TextIO) -> Any:
    """Parse one of our YAML sources, naming the file a syntax error is in.

    Every profile is loaded whatever the command, so one misindented key in
    an unrelated profile stopped `verify.py --emulator handy` on a 37-line
    traceback, the faulty file named only near its end.
    """
    if yaml is None:
        return yaml_load(stream)
    try:
        return yaml_load(stream)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"{stream.name}:{mark.line + 1}" if mark else stream.name
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise SourceUnreadable(
            f"{where}: {problem}. Check it with: "
            "python scripts/validate_schemas.py --source-only"
        ) from None
