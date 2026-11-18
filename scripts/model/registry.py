"""The platform registry and the data directory registry."""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.cli import InputMissing
from model.sources import source_yaml


def load_data_dir_registry(platforms_dir: str = "platforms") -> dict:
    """Load the data directory registry from _data_dirs.yml."""
    registry_path = os.path.join(platforms_dir, "_data_dirs.yml")
    if not os.path.exists(registry_path):
        return {}
    with open(registry_path) as f:
        data = source_yaml(f) or {}
    return data.get("data_directories", {})


def load_platform_registry(platforms_dir: str = "platforms") -> dict:
    """Return the `platforms:` mapping from _registry.yml, empty if absent."""
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if not os.path.exists(registry_path):
        return {}
    with open(registry_path) as f:
        return (source_yaml(f) or {}).get("platforms", {})


def list_registered_platforms(platforms_dir: str = "platforms") -> list[str]:
    """List platforms registered in _registry.yml.

    Only registered platforms generate packs and appear in CI.
    Unregistered YAMLs (e.g., emulatorjs.yml) are base configs for inheritance.

    A missing registry, or a registered platform whose file is gone, raises:
    left out quietly, verify --all --strict and every --all build passed
    having checked none of it, and install.py kept serving its last manifest.
    """
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if not os.path.exists(registry_path):
        raise InputMissing(f"no platform registry at {registry_path}")
    with open(registry_path) as f:
        registry = source_yaml(f) or {}
    platforms = []
    for name, meta in sorted(registry.get("platforms", {}).items()):
        config_path = os.path.join(platforms_dir, meta.get("config", f"{name}.yml"))
        if not os.path.exists(config_path):
            raise FileNotFoundError(
                f"{name} is registered in {registry_path} but {config_path} does not exist"
            )
        platforms.append(name)
    return platforms


def list_release_pack_platforms(platforms_dir: str = "platforms") -> list[str]:
    """Registered platforms a release publishes a ZIP pack for.

    `release_pack: true` in _registry.yml is the whole list: the build of
    `--all`, the pack checks, the release record and every download table
    read it. The other platforms keep their install manifest and are served
    by the installer.
    """
    registry = load_platform_registry(platforms_dir)
    return [
        name
        for name in list_registered_platforms(platforms_dir)
        if registry.get(name, {}).get("release_pack") is True
    ]


VERSIONS_FILE = "data/.versions.json"


def _load_versions(versions_path: str = VERSIONS_FILE) -> dict[str, dict]:
    path = Path(versions_path)
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)
