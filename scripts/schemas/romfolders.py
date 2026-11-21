"""The scraped rom folder setups and the sources their refs name."""

from __future__ import annotations

import core.paths
from core.paths import PLATFORMS_DIR
from model.romfolders import source_refs, split_refs
from model.safeparse import yaml_load
from schemas.validators import schema_errors, schema_validator


def romfolder_errors() -> list[str]:
    """Every scraped setup against its schema, and every source_ref against
    the sources the file declares: a ref naming no declared repository can
    never be read back at a pin."""
    directory = core.paths.REPO_ROOT / PLATFORMS_DIR / "romfolders"
    if not directory.is_dir():
        return []
    validator = schema_validator("romfolders.schema.json")
    out: list[str] = []
    for path in sorted(directory.glob("*.yml")):
        label = str(path.relative_to(core.paths.REPO_ROOT))
        with path.open(encoding="utf-8") as handle:
            data = yaml_load(handle)
        errors = schema_errors(validator, data, label)
        out.extend(errors)
        if errors:
            continue
        declared = set(data["sources"])
        for ref in source_refs(data):
            try:
                parts = split_refs(ref)
            except ValueError as exc:
                out.append(f"{label}: {exc}")
                continue
            for key, path, lines in parts:
                if key not in declared:
                    part = f"{key} {path}" + (f":{lines}" if lines else "")
                    out.append(f"{label}: source_ref {part!r} names undeclared source {key!r}")
    return out
