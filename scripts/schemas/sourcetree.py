"""The emulators/ and platforms/ trees against their schemas and invariants."""

from __future__ import annotations

from pathlib import Path

import yaml

import core.paths
from core.paths import EMULATORS_DIR, PLATFORMS_DIR
from model.profiles import source_yaml_paths
from model.registry import load_data_dir_registry
from schemas.citations import data_only_source_refs, doubled_paths, unreachable_citations
from schemas.platformchecks import config_records_without_evidence
from schemas.profilechecks import (
    checks_without_values,
    config_reads_without_build,
    group_requirement_split,
    save_dir_without_library_name,
    systems_outside_profile,
)
from schemas.sources import load_source, source_mapping
from schemas.validators import schema_errors, schema_validator


def validate_yaml_directory(
    directory: Path,
    schema_name: str,
    *,
    skip_private: bool = False,
) -> list[str]:
    validator = schema_validator(schema_name)
    out: list[str] = []
    for path in source_yaml_paths(directory):
        if skip_private and path.name.startswith("_"):
            continue
        try:
            data = load_source(path)
        except (OSError, yaml.YAMLError) as exc:
            out.append(f"{path.relative_to(core.paths.REPO_ROOT)}: {exc}")
            continue
        out.extend(schema_errors(validator, data, str(path.relative_to(core.paths.REPO_ROOT))))
        out.extend(unreachable_citations(path, data))
        if schema_name == "platform.schema.json":
            out.extend(config_records_without_evidence(path, data))
        if schema_name == "emulator.schema.json":
            out.extend(config_reads_without_build(path, data))
            out.extend(checks_without_values(path, data))
            out.extend(save_dir_without_library_name(path, data))
            out.extend(systems_outside_profile(path, data))
            out.extend(doubled_paths(path))
            out.extend(group_requirement_split(path, data))
            out.extend(data_only_source_refs(path, data))
    return out


def unknown_data_dir_refs() -> list[str]:
    """data_directories refs the registry does not define.

    A ref nobody registers is never fetched: yaps2 named yaps2-resources and
    every run printed "not cached" while refresh_data_dirs had nothing to
    refresh.
    """
    registered = set(load_data_dir_registry(core.paths.REPO_ROOT / PLATFORMS_DIR, required=True))
    out: list[str] = []
    for directory in (core.paths.REPO_ROOT / EMULATORS_DIR, core.paths.REPO_ROOT / PLATFORMS_DIR):
        for path in source_yaml_paths(directory):
            if path.name.startswith("_"):
                continue
            document = source_mapping(path)
            systems = document.get("systems")
            holders = [document, *(systems.values() if isinstance(systems, dict) else [])]
            for holder in holders:
                if not isinstance(holder, dict):
                    continue
                for entry in holder.get("data_directories") or []:
                    ref = entry.get("ref") if isinstance(entry, dict) else None
                    if ref and ref not in registered:
                        out.append(
                            f"{path.relative_to(core.paths.REPO_ROOT)}: data directory {ref!r} "
                            f"is not in platforms/_data_dirs.yml"
                        )
    return out


def repository_layout_in_profiles() -> list[str]:
    """Profile destinations that name this repository's storage.

    `path:` is where the emulator's code reads the file, never where we keep
    it: a profile written from a clone filed its variants under
    `.variants/...`, and the pack then wrote them where no emulator looks.
    """
    out: list[str] = []
    for path in source_yaml_paths(core.paths.REPO_ROOT / EMULATORS_DIR):
        document = source_mapping(path)
        for entry in document.get("files") or []:
            if not isinstance(entry, dict):
                continue
            for key in ("path", "standalone_path"):
                value = str(entry.get(key) or "")
                if ".variants" in value.replace("\\", "/").split("/"):
                    out.append(
                        f"{path.relative_to(core.paths.REPO_ROOT)}: {entry.get('name')} {key} "
                        f"names the repository's .variants/ storage: {value}"
                    )
    return out
