"""Exporter plugin discovery module.

Auto-detects *_exporter.py files and exposes their exporters.
Each exporter module must define an Exporter class inheriting BaseExporter.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from .base_exporter import BaseExporter

_exporters: dict[str, type] = {}


def discover_exporters() -> dict[str, type]:
    """Auto-discover *_exporter.py modules, return {platform: ExporterClass}."""
    if _exporters:
        return _exporters

    package_dir = Path(__file__).parent

    for _finder, name, _ispkg in pkgutil.iter_modules([str(package_dir)]):
        if not name.endswith("_exporter") or name == "base_exporter":
            continue

        module = importlib.import_module(f".{name}", package=__package__)
        exporter_class = getattr(module, "Exporter", None)

        if exporter_class and issubclass(exporter_class, BaseExporter):
            _exporters[exporter_class.platform_name()] = exporter_class

    return _exporters
