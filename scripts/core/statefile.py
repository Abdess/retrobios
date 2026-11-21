"""State files of unattended jobs: UTC timestamps and atomic JSON writes."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from core.artifacts import write_text_atomic


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(path, json.dumps(state, indent=2, sort_keys=True) + "\n")
