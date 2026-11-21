"""The file entries the registered platforms and the emulator profiles declare, and their hash fields."""

from __future__ import annotations

from pathlib import Path

from model.profiles import source_yaml_paths
from model.registry import list_registered_platforms
from model.sources import source_yaml_file


def hash_values(value: object) -> list[str]:
    """A hash field as lowercase values, whether written alone or as a list."""
    if not value:
        return []
    values = value if isinstance(value, list) else str(value).split(",")
    return [str(v).strip().lower() for v in values if str(v).strip()]


def declarations(platforms_dir: Path, emulators_dir: Path) -> list[dict]:
    """Every file entry the registered platforms and the profiles declare."""
    sources = [
        platforms_dir / f"{name}.yml"
        for name in list_registered_platforms(str(platforms_dir))
    ] if platforms_dir.is_dir() else []
    entries: list[dict] = []
    for source in sources:
        config = source_yaml_file(source) or {}
        for system in (config.get("systems") or {}).values():
            entries.extend(system.get("files") or [])
    if emulators_dir.is_dir():
        for source in source_yaml_paths(emulators_dir):
            entries.extend((source_yaml_file(source) or {}).get("files") or [])
    return entries
