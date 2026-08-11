#!/usr/bin/env python3
"""Validate source and generated RetroBIOS data contracts."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path, PurePosixPath

import yaml

from common import yaml_load
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"


def _load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _validator(name: str) -> Draft202012Validator:
    schema = _load_json(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _errors(validator: Draft202012Validator, data: object, label: str) -> list[str]:
    out: list[str] = []
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.path)):
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        out.append(f"{label}:{location}: {error.message}")
    return out


def _validate_yaml_directory(
    directory: Path,
    schema_name: str,
    *,
    skip_private: bool = False,
) -> list[str]:
    validator = _validator(schema_name)
    out: list[str] = []
    for path in sorted(directory.glob("*.yml")):
        if skip_private and path.name.startswith("_"):
            continue
        try:
            with path.open(encoding="utf-8") as handle:
                data = yaml_load(handle)
        except (OSError, yaml.YAMLError) as exc:
            out.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        out.extend(_errors(validator, data, str(path.relative_to(ROOT))))
    return out


def _validate_json_files(paths: list[Path], schema_name: str) -> list[str]:
    validator = _validator(schema_name)
    out: list[str] = []
    for path in paths:
        try:
            data = _load_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            out.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        out.extend(_errors(validator, data, str(path.relative_to(ROOT))))
    return out


def _validate_pack_manifests(dist: Path) -> list[str]:
    """Validate the integrity manifest each generated pack carries.

    generate_pack.py writes manifest.json inside the archive, not beside it,
    so a filesystem glob over dist/ matches nothing and silently validates
    zero documents.

    Reading a pack while a build is writing it reports "File is not a zip
    file" about an archive that is merely half-written, so this takes the same
    shared lock --verify-packs does. A build holding the exclusive lock means
    the packs on disk are mid-flight and there is nothing stable to validate.
    """
    if not dist.is_dir():
        return []

    sys.path.insert(0, str(ROOT / "scripts"))
    from common import ArtifactLockBusy, artifact_lock

    try:
        with artifact_lock(str(dist), exclusive=False):
            return _scan_pack_manifests(dist)
    except ArtifactLockBusy:
        print(
            f"note: {dist.name} is being written; skipping pack manifests",
            file=sys.stderr,
        )
        return []


def _scan_pack_manifests(dist: Path) -> list[str]:
    validator = _validator("pack-manifest.schema.json")

    def _label(path: Path) -> str:
        resolved = path.resolve()
        try:
            return str(resolved.relative_to(ROOT))
        except ValueError:
            return str(resolved)

    out: list[str] = []
    for archive in sorted(dist.glob("*.zip")):
        try:
            with zipfile.ZipFile(archive) as handle:
                members = [
                    name
                    for name in handle.namelist()
                    if PurePosixPath(name).name == "manifest.json"
                ]
                for member in members:
                    label = f"{_label(archive)}:{member}"
                    try:
                        document = json.loads(handle.read(member).decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        out.append(f"{label}: {exc}")
                        continue
                    out.extend(_errors(validator, document, label))
        except (OSError, zipfile.BadZipFile) as exc:
            out.append(f"{_label(archive)}: {exc}")
    return out


def _semantic_envelope_checks(path: Path, document: dict) -> list[str]:
    if document.get("count") != len(document.get("items", [])):
        return [f"{path.relative_to(ROOT)}: count does not equal len(items)"]
    return []


def _semantic_database_checks(database: dict) -> list[str]:
    out: list[str] = []
    files = database.get("files", {})
    if database.get("total_files") != len(files):
        out.append("database.json: total_files does not equal len(files)")
    if database.get("total_size") != sum(entry.get("size", 0) for entry in files.values()):
        out.append("database.json: total_size does not equal the file-size sum")
    # One path holds one content. Two entries naming the same path means one
    # of them declares a hash the file at that path does not have.
    owners: dict[str, str] = {}
    for sha1, entry in files.items():
        if entry.get("sha1") != sha1:
            out.append(f"database.json: files/{sha1}: key and sha1 differ")
        path = entry.get("path", "")
        if not path:
            continue
        first = owners.setdefault(path, sha1)
        if first != sha1:
            out.append(
                f"database.json: {path} is claimed by {first} and {sha1}"
            )
    return out


def _semantic_install_checks(path: Path, manifest: dict) -> list[str]:
    out: list[str] = []
    files = manifest.get("files", [])
    if manifest.get("total_files") != len(files):
        out.append(f"{path.relative_to(ROOT)}: total_files does not equal len(files)")
    if manifest.get("total_size") != sum(entry.get("size", 0) for entry in files):
        out.append(f"{path.relative_to(ROOT)}: total_size does not equal the file-size sum")
    omitted = manifest.get("omitted_files", [])
    if manifest.get("total_omitted") != len(omitted):
        out.append(
            f"{path.relative_to(ROOT)}: total_omitted does not equal "
            "len(omitted_files)"
        )
    destinations = [entry.get("dest") for entry in files]
    if len(destinations) != len(set(destinations)):
        out.append(f"{path.relative_to(ROOT)}: duplicate destinations")
    omitted_destinations = [entry.get("dest") for entry in omitted]
    if len(omitted_destinations) != len(set(omitted_destinations)):
        out.append(f"{path.relative_to(ROOT)}: duplicate omitted destinations")
    overlap = set(destinations) & set(omitted_destinations)
    if overlap:
        out.append(
            f"{path.relative_to(ROOT)}: destinations are both downloadable and omitted"
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="validate emulator/platform YAML only",
    )
    args = parser.parse_args()

    errors: list[str] = []
    errors.extend(
        _validate_yaml_directory(ROOT / "emulators", "emulator.schema.json")
    )
    errors.extend(
        _validate_yaml_directory(
            ROOT / "platforms", "platform.schema.json", skip_private=True
        )
    )

    if not args.source_only:
        database_path = ROOT / "database.json"
        errors.extend(_validate_json_files([database_path], "database.schema.json"))
        if database_path.exists():
            errors.extend(_semantic_database_checks(_load_json(database_path)))

        install_paths = sorted((ROOT / "install").glob("*.json"))
        errors.extend(
            _validate_json_files(install_paths, "install-manifest.schema.json")
        )
        for path in install_paths:
            errors.extend(_semantic_install_checks(path, _load_json(path)))

        target_paths = sorted((ROOT / "install" / "targets").glob("*.json"))
        errors.extend(
            _validate_json_files(target_paths, "target-manifest.schema.json")
        )

        stats_path = ROOT / "docs" / "stats.json"
        if stats_path.exists():
            errors.extend(_validate_json_files([stats_path], "stats.schema.json"))

        api_dir = ROOT / "docs" / "api" / "v1"
        api_database = api_dir / "database.json"
        if api_database.exists():
            errors.extend(
                _validate_json_files([api_database], "database.schema.json")
            )
        api_stats = api_dir / "stats.json"
        if api_stats.exists():
            errors.extend(_validate_json_files([api_stats], "stats.schema.json"))
        envelope_paths = [
            api_dir / name
            for name in ("catalog.json", "platforms.json", "emulators.json", "gaps.json")
            if (api_dir / name).exists()
        ]
        errors.extend(
            _validate_json_files(envelope_paths, "site-api-envelope.schema.json")
        )
        for path in envelope_paths:
            errors.extend(_semantic_envelope_checks(path, _load_json(path)))

        errors.extend(_validate_pack_manifests(ROOT / "dist"))

    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"{len(errors)} schema or semantic error(s)")
        return 1
    print("All RetroBIOS schemas and semantic invariants are valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
