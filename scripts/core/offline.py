"""Whether a run fetches nothing: the one rule core.upstream and its callers read."""

from __future__ import annotations

import os

# Set, this run fetches nothing whatever its callers pass: the test runners
# and the PR checks set it.
OFFLINE_ENV = "RETROBIOS_OFFLINE"


def run_is_offline(offline: bool | None = False) -> bool:
    """Whether this run fetches nothing: the caller's flag, or RETROBIOS_OFFLINE."""
    return bool(offline) or bool(os.environ.get(OFFLINE_ENV))
