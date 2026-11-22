"""The emulator field of a platform launcher record: one name, or several joined."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# A record written once for several emulators names them all in one field
# (schemas/platform.schema.json, launchers[].emulator).
SEPARATOR = ", "


def join_emulators(names: Iterable[str]) -> str:
    """The emulator field of a record written for `names`."""
    return SEPARATOR.join(names)


def emulator_names(field: str) -> list[str]:
    """The names an emulator field joins, in their order."""
    return [name.strip() for name in field.split(",")]


def record_emulators(record: Mapping[str, Any]) -> list[str]:
    """The emulators a launcher record is written for."""
    return emulator_names(str(record.get("emulator", "")))
