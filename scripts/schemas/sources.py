"""The source YAML files, parsed once per run whichever check reads them."""

from __future__ import annotations

from pathlib import Path

from model.safeparse import yaml_load


_SOURCES: dict[tuple[Path, int, int], object] = {}


def load_source(path: Path) -> object:
    """A source YAML, parsed once per run whichever check reads it: the
    schema pass, the data directory refs and the layout check each parsed
    all 649 profiles again. Keyed by size and mtime too, so a file written
    again in the same process is read again."""
    stat = path.stat()
    key = (path, stat.st_mtime_ns, stat.st_size)
    if key not in _SOURCES:
        with path.open(encoding="utf-8") as handle:
            _SOURCES[key] = yaml_load(handle)
    return _SOURCES[key]


def source_mapping(path: Path) -> dict:
    """A source YAML that holds a mapping, empty when the file is."""
    document = load_source(path)
    if not document:
        return {}
    if not isinstance(document, dict):
        raise ValueError(f"{path}: not a mapping")
    return document
