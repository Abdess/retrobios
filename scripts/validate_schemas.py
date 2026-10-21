#!/usr/bin/env python3
"""Validate source and generated RetroBIOS data contracts."""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import yaml

from common import source_yaml_paths, yaml_load
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
    for path in source_yaml_paths(directory):
        if skip_private and path.name.startswith("_"):
            continue
        try:
            with path.open(encoding="utf-8") as handle:
                data = yaml_load(handle)
        except (OSError, yaml.YAMLError) as exc:
            out.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        out.extend(_errors(validator, data, str(path.relative_to(ROOT))))
        out.extend(_unreachable_citations(path, data))
        if schema_name == "emulator.schema.json":
            out.extend(_checks_without_values(path, data))
            out.extend(_systems_outside_profile(path, data))
            out.extend(_doubled_paths(path))
    return out


_CHECK_FIELDS = {
    "crc32": ("crc32",),
    "md5": ("md5",),
    "sha1": ("sha1",),
    "sha256": ("sha256",),
    "size": ("size", "min_size", "max_size"),
}


def _systems_outside_profile(path: Path, document: object) -> list[str]:
    """An entry's system: or systems: naming a system its profile does not list.

    A --system pick selects the profile by its systems: and then the entry
    by its own, so a name the profile lacks is one no pick ever reaches.
    """
    if not isinstance(document, dict):
        return []
    listed = {str(s) for s in document.get("systems") or []}
    out: list[str] = []
    for index, entry in enumerate(document.get("files") or []):
        if not isinstance(entry, dict):
            continue
        named = [entry["system"]] if entry.get("system") else []
        named += list(entry.get("systems") or [])
        unknown = [str(s) for s in named if str(s) not in listed]
        if unknown:
            out.append(
                f"{path.relative_to(ROOT)}: files[{index}] ({entry.get('name')}) "
                f"system {', '.join(unknown)} not in the profile's systems"
            )
    return out


def _checks_without_values(path: Path, document: object) -> list[str]:
    """A check an entry declares with nothing to compare against.

    validation: [crc32] with no crc32 runs nothing: the file passes whatever
    it holds, and the report reads as checked. Fourteen profiles carried
    one, the code they describe either refusing or warning on a value the
    entry never wrote down.
    """
    out: list[str] = []
    files = document.get("files") if isinstance(document, dict) else None
    for index, entry in enumerate(files or []):
        if not isinstance(entry, dict):
            continue
        declared = entry.get("validation") or []
        if isinstance(declared, dict):
            declared = [check for checks in declared.values() for check in checks or []]
        for check in declared:
            fields = _CHECK_FIELDS.get(check)
            if fields and not any(entry.get(field) not in (None, "", []) for field in fields):
                out.append(
                    f"{path.relative_to(ROOT)}: files[{index}] ({entry.get('name')}) "
                    f"declares a {check} check with no {'/'.join(fields)} value"
                )
    return out


def _validate_json_files(
    paths: list[Path],
    schema_name: str,
    semantic_check: Callable[[Path, object], list[str]] | None = None,
) -> list[str]:
    validator = _validator(schema_name)
    out: list[str] = []
    for path in paths:
        try:
            data = _load_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            out.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        validation_errors = _errors(validator, data, str(path.relative_to(ROOT)))
        out.extend(validation_errors)
        if not validation_errors and semantic_check is not None:
            out.extend(semantic_check(path, data))
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
            f"note: {dist.name} is being written, skipping pack manifests",
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


_UNREACHABLE_REF = re.compile(
    r"(?:^|[\s,;(])(?:tmp/|/|[A-Za-z]:[\\/]|\.{1,2}/)[\w.\\/+-]*[\w+-]:\d+(?:-\d+)?"
)


def _unreachable_citations(path: Path, document: object) -> list[str]:
    """Refs naming a place no repository can hold.

    A citation is read against a revision of a declared repository, so a
    scratch directory, an absolute path or one climbing out of the tree can
    never resolve and never will. kenji-nx carried tmp/es-de/ANDROID.md:470,
    a path from whoever profiled it, which profile_sync could only report
    missing forever.
    """
    out: list[str] = []
    stack: list[object] = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            for match in _UNREACHABLE_REF.finditer(node):
                out.append(
                    f"{path.relative_to(ROOT)}: citation names a path outside "
                    f"any repository: {match.group().strip(' ,;(')}"
                )
    return out


_DOUBLED_PATH = re.compile(r"((?:[\w.-]+/){2,})\1")


def _doubled_paths(path: Path) -> list[str]:
    """A citation whose directory is written twice in a row.

    Read from the raw text, comments included: primehack's note on the
    Realtek loader cited Source/Core/Core/IOS/USB/Bluetooth/ twice over, a
    path no revision holds, in a comment the parsed document never shows.
    """
    out: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = _DOUBLED_PATH.search(line)
        if match:
            out.append(
                f"{path.relative_to(ROOT)}:{number}: citation repeats its "
                f"directory: {match.group(1)}"
            )
    return out


def _unknown_data_dir_refs() -> list[str]:
    """data_directories refs the registry does not define.

    A ref nobody registers is never fetched: yaps2 named yaps2-resources and
    every run printed "not cached" while refresh_data_dirs had nothing to
    refresh.
    """
    registry_path = ROOT / "platforms" / "_data_dirs.yml"
    with registry_path.open(encoding="utf-8") as handle:
        registered = set((yaml_load(handle) or {}).get("data_directories", {}))
    out: list[str] = []
    for directory in (ROOT / "emulators", ROOT / "platforms"):
        for path in source_yaml_paths(directory):
            if path.name.startswith("_"):
                continue
            with path.open(encoding="utf-8") as handle:
                document = yaml_load(handle) or {}
            systems = document.get("systems")
            holders = [document, *(systems.values() if isinstance(systems, dict) else [])]
            for holder in holders:
                if not isinstance(holder, dict):
                    continue
                for entry in holder.get("data_directories") or []:
                    ref = entry.get("ref") if isinstance(entry, dict) else None
                    if ref and ref not in registered:
                        out.append(
                            f"{path.relative_to(ROOT)}: data directory {ref!r} "
                            f"is not in platforms/_data_dirs.yml"
                        )
    return out


def _repository_layout_in_profiles() -> list[str]:
    """Profile destinations that name this repository's storage.

    `path:` is where the emulator's code reads the file, never where we keep
    it: a profile written from a clone filed its variants under
    `.variants/...`, and the pack then wrote them where no emulator looks.
    """
    out: list[str] = []
    for path in source_yaml_paths(ROOT / "emulators"):
        with path.open(encoding="utf-8") as handle:
            document = yaml_load(handle) or {}
        for entry in document.get("files") or []:
            if not isinstance(entry, dict):
                continue
            for key in ("path", "standalone_path"):
                value = str(entry.get(key) or "")
                if ".variants" in value.replace("\\", "/").split("/"):
                    out.append(
                        f"{path.relative_to(ROOT)}: {entry.get('name')} {key} "
                        f"names the repository's .variants/ storage: {value}"
                    )
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


def unchecked_formats() -> list[str]:
    """Formats the schemas declare that this jsonschema install cannot check.

    date-time and uri need the format extras. Without them the ten format
    constraints of the published schemas were accepted unread.
    """
    used = {
        match
        for path in SCHEMAS.glob("*.json")
        for match in re.findall(r'"format"\s*:\s*"([^"]+)"', path.read_text(encoding="utf-8"))
    }
    return sorted(used - set(FormatChecker().checkers))


def _format_errors() -> list[str]:
    """jsonschema skips a format it has no checker for: say so, and fail."""
    return [
        f"no checker for format {name}: install \"jsonschema[format-nongpl]\""
        for name in unchecked_formats()
    ]


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="validate emulator/platform YAML only",
    )
    args = parser.parse_args()

    errors: list[str] = _format_errors()
    errors.extend(
        _validate_yaml_directory(ROOT / "emulators", "emulator.schema.json")
    )
    errors.extend(
        _validate_yaml_directory(
            ROOT / "platforms", "platform.schema.json", skip_private=True
        )
    )
    errors.extend(_unknown_data_dir_refs())
    errors.extend(_repository_layout_in_profiles())

    if not args.source_only:
        database_path = ROOT / "database.json"
        errors.extend(
            _validate_json_files(
                [database_path],
                "database.schema.json",
                lambda _path, database: _semantic_database_checks(database),
            )
        )

        install_paths = sorted((ROOT / "install").glob("*.json"))
        errors.extend(
            _validate_json_files(
                install_paths, "install-manifest.schema.json", _semantic_install_checks
            )
        )

        target_paths = sorted((ROOT / "install" / "targets").glob("*.json"))
        errors.extend(
            _validate_json_files(target_paths, "target-manifest.schema.json")
        )

        release_path = ROOT / "release.json"
        if release_path.exists():
            errors.extend(_validate_json_files([release_path], "release.schema.json"))

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
        ] + sorted((api_dir / "platforms").glob("*.json")) + sorted(
            (api_dir / "systems").glob("*.json")
        )
        errors.extend(
            _validate_json_files(
                envelope_paths,
                "site-api-envelope.schema.json",
                _semantic_envelope_checks,
            )
        )

        errors.extend(_validate_pack_manifests(ROOT / "dist"))

    if errors:
        for error in errors:
            print(f"ERROR {error}")
        print(f"{len(errors)} schema or semantic error(s)")
        return 1
    print("All RetroBIOS schemas and semantic invariants are valid.")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
