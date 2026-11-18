"""The campaign's state file: what each check ran against, and whether it runs again."""

from __future__ import annotations

import json
from pathlib import Path

from model import measurements as mr


STATE_VERSION = 1

DONE = "done"
FAILED = "failed"
PENDING = "pending"


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        state = {}
    state.setdefault("version", STATE_VERSION)
    for key in ("checks", "cores", "content", "builds", "emulators"):
        state.setdefault(key, {})
    return state



def should_run(previous: dict | None, core_sha: str, digest: str, oracle_sha: str = "") -> bool:
    """A check runs again when it never ran, is pending, or ran against
    another core build, another version of the profile, another oracle, or
    before records carried a verdict."""
    if not previous:
        return True
    if previous.get("status") == PENDING:
        return True
    return (previous.get("core_sha256") != core_sha or previous.get("profile_digest") != digest
            or previous.get("record_version") != mr.RECORD_VERSION
            or previous.get("oracle_sha256", "") != oracle_sha)
