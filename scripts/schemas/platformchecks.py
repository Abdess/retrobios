"""Platform file invariants: launcher records and the config evidence they cite."""

from __future__ import annotations

from pathlib import Path

import core.paths
from resolve.launcherrefs import config_ref, is_feature_ref


def config_records_without_evidence(path: Path, document: object) -> list[str]:
    """A launcher record citing a config without the links its extractor reads.

    A config file is proof only when the code installing it and the code
    reading it are shown (launchers.config_evidence). The platform's half
    is the extractor's to write: a record citing a shipped config carries
    installs and overrides, and a feature or option file is never a
    record's source, only its choices_from.
    """
    if not isinstance(document, dict):
        return []
    out: list[str] = []
    for index, record in enumerate(document.get("launchers") or []):
        if not isinstance(record, dict):
            continue
        cited = config_ref(str(record.get("source_ref") or ""))
        where = f"{path.relative_to(core.paths.REPO_ROOT)}: launchers[{index}] ({record.get('emulator')})"
        features = [part for part in cited if is_feature_ref(part)]
        if features:
            out.append(f"{where} cites {features[0]} as source, choices_from holds it")
        if [part for part in cited if not is_feature_ref(part)] and not (
            record.get("installs") and "overrides" in record
        ):
            out.append(f"{where} cites a config without installs and overrides")
    return out
