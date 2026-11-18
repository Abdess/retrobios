"""State files of unattended jobs: UTC timestamps and atomic JSON writes."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_suffix(".tmp")
    scratch.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(scratch, path)
