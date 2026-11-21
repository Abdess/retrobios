"""The record lines under measurements/ against their schemas."""

from __future__ import annotations

import json
from pathlib import Path

import core.paths
from model import measurements as mr
from schemas.validators import schema_errors, schema_validator


def measurement_errors(root: Path | None = None) -> list[str]:
    """Every record line under measurements/, against its schema and the
    rules model.measurements.read_records applies."""
    root = root or core.paths.REPO_ROOT
    validator = schema_validator("core-probe-record.schema.json")
    out: list[str] = []
    campaign = {mr.records_path(name): schema_validator(schema)
                for name, (_, schema) in mr.CAMPAIGN_FILES.items()}
    for path, file in sorted(mr.tree_files(root).items()):
        if not path.endswith(".jsonl"):
            continue
        for number, line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                out.append(f"{path}:{number}: {exc}")
                continue
            out.extend(schema_errors(campaign.get(path, validator), record, f"{path}:{number}"))
    if not out:
        try:
            mr.read_records(root)
            for name in mr.CAMPAIGN_FILES:
                mr.read_campaign(root, name)
        except mr.MeasurementsError as exc:
            out.append(str(exc))
    return out
