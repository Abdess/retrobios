"""Every check of a validation run, in the order the command reports them."""

from __future__ import annotations

import core.paths
from core.paths import DB_FILE, EMULATORS_DIR, PLATFORMS_DIR
from schemas.documents import (
    semantic_database_checks,
    semantic_envelope_checks,
    validate_json_files,
)
from schemas.events import event_schema_errors
from schemas.games import arcade_pin_errors, games_index_errors, games_source_errors
from schemas.installs import semantic_install_checks, semantic_standalone_checks
from schemas.measurements import measurement_errors
from schemas.packmanifests import validate_pack_manifests
from schemas.registry import registry_contract, save_directory_blocks
from schemas.romfolders import romfolder_errors
from schemas.sourcetree import (
    repository_layout_in_profiles,
    unknown_data_dir_refs,
    validate_yaml_directory,
)
from schemas.validators import format_errors


def source_errors() -> list[str]:
    """The emulator and platform sources and the data committed beside them."""
    root = core.paths.REPO_ROOT
    errors: list[str] = format_errors()
    errors.extend(
        validate_yaml_directory(root / EMULATORS_DIR, "emulator.schema.json")
    )
    errors.extend(
        validate_yaml_directory(
            root / PLATFORMS_DIR, "platform.schema.json", skip_private=True
        )
    )
    errors.extend(unknown_data_dir_refs())
    errors.extend(repository_layout_in_profiles())
    errors.extend(save_directory_blocks())
    errors.extend(registry_contract())
    errors.extend(event_schema_errors())
    errors.extend(measurement_errors())
    errors.extend(romfolder_errors())
    errors.extend(games_source_errors())
    errors.extend(arcade_pin_errors())
    return errors


def generated_errors() -> list[str]:
    """The generated artifacts: database, install lists, site data and packs."""
    root = core.paths.REPO_ROOT
    errors = validate_json_files(
        [root / DB_FILE],
        "database.schema.json",
        lambda _path, database: semantic_database_checks(database),
    )

    install_paths = sorted((root / "install").glob("*.json"))
    errors.extend(
        validate_json_files(
            install_paths, "install-manifest.schema.json", semantic_install_checks
        )
    )

    standalone_paths = sorted((root / "install" / "standalone").glob("*.json"))
    errors.extend(
        validate_json_files(
            standalone_paths, "install-standalone.schema.json",
            semantic_standalone_checks,
        )
    )

    target_paths = sorted((root / "install" / "targets").glob("*.json"))
    errors.extend(
        validate_json_files(target_paths, "target-manifest.schema.json")
    )

    release_path = root / "release.json"
    if release_path.exists():
        errors.extend(validate_json_files([release_path], "release.schema.json"))

    stats_path = root / "website" / "public" / "stats.json"
    if stats_path.exists():
        errors.extend(validate_json_files([stats_path], "stats.schema.json"))

    errors.extend(_site_api_errors())
    errors.extend(games_index_errors())
    errors.extend(validate_pack_manifests(root / "dist"))
    return errors


def _site_api_errors() -> list[str]:
    """The documents the site publishes under api/v1/."""
    api_dir = core.paths.REPO_ROOT / "website" / "public" / "api" / "v1"
    errors: list[str] = []
    api_database = api_dir / "database.json"
    if api_database.exists():
        errors.extend(
            validate_json_files([api_database], "database.schema.json")
        )
    api_stats = api_dir / "stats.json"
    if api_stats.exists():
        errors.extend(validate_json_files([api_stats], "stats.schema.json"))
    envelope_paths = [
        api_dir / name
        for name in ("catalog.json", "platforms.json", "emulators.json", "gaps.json")
        if (api_dir / name).exists()
    ] + sorted((api_dir / "platforms").glob("*.json")) + sorted(
        (api_dir / "systems").glob("*.json")
    ) + sorted((api_dir / "lookup").glob("*.json"))
    errors.extend(
        validate_json_files(
            envelope_paths,
            "site-api-envelope.schema.json",
            semantic_envelope_checks,
        )
    )
    return errors


def validation_errors(source_only: bool) -> list[str]:
    """Every error of a run: the sources, then the generated artifacts unless
    ``source_only``."""
    errors = source_errors()
    if not source_only:
        errors.extend(generated_errors())
    return errors
