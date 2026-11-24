"""The games-on-card sources, the arcade pins and the published games index."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import core.paths
from core.paths import EMULATORS_DIR
from model.safeparse import yaml_load
from schemas.sources import source_mapping
from schemas.validators import defs_validator, json_object, schema_errors, schema_validator


# Source data of the games-on-card mode: file pattern -> schema.
_GAMES_SOURCES = (
    ("games/catalogs/*/*.json", "game-catalog.schema.json"),
    ("games/arcade/*.json", "arcade-parents.schema.json"),
    ("games/headers.yml", "game-headers.schema.json"),
    ("games/regions.yml", "game-regions.schema.json"),
    ("games/extras.yml", "game-extras.schema.json"),
)


def games_source_errors() -> list[str]:
    out: list[str] = []
    for pattern, schema in _GAMES_SOURCES:
        paths = sorted(core.paths.REPO_ROOT.glob(pattern))
        if not paths:
            continue
        validator = schema_validator(schema)
        for path in paths:
            with path.open(encoding="utf-8") as handle:
                data = json.load(handle) if path.suffix == ".json" else yaml_load(handle)
            out.extend(schema_errors(validator, data, str(path.relative_to(core.paths.REPO_ROOT))))
    return out


def arcade_pin_errors() -> list[str]:
    """games/arcade/<profile>.json read at the revision and version its
    profile pins. A bump of the profile left the game-to-BIOS map of the old
    code in place, and the installer kept serving it."""
    out: list[str] = []
    for path in sorted((core.paths.REPO_ROOT / "games" / "arcade").glob("*.json")):
        doc = json_object(path)
        profile_path = core.paths.REPO_ROOT / EMULATORS_DIR / f"{doc.get('profile')}.yml"
        label = str(path.relative_to(core.paths.REPO_ROOT))
        if not profile_path.is_file():
            out.append(f"{label}: no profile emulators/{profile_path.name}")
            continue
        profile = source_mapping(profile_path)
        pinned = profile.get("source_commit")
        pins = set(pinned.values()) if isinstance(pinned, dict) else {pinned}
        commit = (doc.get("source") or {}).get("commit")
        drifted = []
        if commit and commit not in pins:
            drifted.append(f"read at {commit[:12]}, the profile pins {pinned}")
        if doc.get("core_version") != profile.get("core_version"):
            drifted.append(f"core_version {doc.get('core_version')!r}, "
                           f"the profile says {profile.get('core_version')!r}")
        if drifted:
            out.append(f"{label}: {'; '.join(drifted)} "
                       f"(python -m scripts.scraper.arcade.arcade_parent_importer --profile {doc.get('profile')})")
    return out


def games_index_errors() -> list[str]:
    """install/games/: each document against its kind, and the index
    against the files it lists (size and sha256)."""
    base = core.paths.REPO_ROOT / "install" / "games"
    index_path = base / "index.json"
    if not index_path.exists():
        return []
    out: list[str] = []
    index = json_object(index_path)
    out.extend(schema_errors(defs_validator("games-index.schema.json", "index"), index,
                       str(index_path.relative_to(core.paths.REPO_ROOT))))
    kinds = {
        "setups": defs_validator("games-index.schema.json", "setup"),
        "fallback": defs_validator("games-index.schema.json", "fallback"),
        "systems": defs_validator("games-index.schema.json", "system"),
        "arcade": schema_validator("arcade-parents.schema.json"),
    }
    listed: set[Path] = set()
    for kind, validator in kinds.items():
        for entry in (index.get(kind) or {}).values():
            path = base / entry["file"]
            listed.add(path)
            label = str(path.relative_to(core.paths.REPO_ROOT))
            if not path.exists():
                out.append(f"{label}: listed in index.json, absent")
                continue
            data = path.read_bytes()
            if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                out.append(f"{label}: size or sha256 differs from index.json")
            out.extend(schema_errors(validator, json.loads(data), label))
    out.extend(f"{path.relative_to(core.paths.REPO_ROOT)}: not listed in index.json"
               for path in sorted(base.rglob("*.json")) if path != index_path and path not in listed)
    return out
