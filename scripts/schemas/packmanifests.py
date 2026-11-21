"""The manifest.json each generated pack carries, read inside the archive."""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path, PurePosixPath

import core.paths
from core.artifacts import ArtifactLockBusy, artifact_lock
from schemas.validators import schema_errors, schema_validator


def validate_pack_manifests(dist: Path) -> list[str]:
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
    validator = schema_validator("pack-manifest.schema.json")
    # The lists a pack carries for the installer, each under its own
    # contract: the schemas name no other file, so they are checked here.
    carried = {
        "install_list": schema_validator("install-manifest.schema.json"),
        "targets": schema_validator("target-manifest.schema.json"),
    }

    def _label(path: Path) -> str:
        resolved = path.resolve()
        try:
            return str(resolved.relative_to(core.paths.REPO_ROOT))
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
                    out.extend(schema_errors(validator, document, label))
                    for key, inner in carried.items():
                        if isinstance(document, dict) and key in document:
                            out.extend(schema_errors(inner, document[key], f"{label}:{key}"))
        except (OSError, zipfile.BadZipFile) as exc:
            out.append(f"{_label(archive)}: {exc}")
    return out
